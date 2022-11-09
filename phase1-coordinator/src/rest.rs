//! REST API endpoints exposed by the [Coordinator](`crate::Coordinator`).

use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read, Write},
};
use tracing::warn;

use crate::{
    objects::{ContributionInfo, LockedLocators},
    rest_utils::{
        self,
        ContributorStatus,
        Coordinator,
        CurrentContributor,
        LazyJson,
        NewParticipant,
        PostChunkRequest,
        ResponseError,
        Result,
        Secret,
        ServerAuth,
        HEALTH_PATH,
        TOKENS_PATH,
        TOKENS_ZIP_FILE,
    },
    s3::S3Ctx,
    CoordinatorState,
    coordinator_state::TokenState,
    Participant,
};
use rocket::{
    get,
    post,
    serde::json::Json,
    tokio::{fs, task},
    Shutdown,
    State,
};

/// Add the incoming contributor to the queue of contributors.
#[post("/contributor/join_queue", format = "json", data = "<token>")]
pub async fn join_queue(
    coordinator: &State<Coordinator>,
    new_participant: NewParticipant,
    token: LazyJson<String>,
) -> Result<()> {
    // NOTE: check on the token happens only here meaning that a contributor can join the ceremony at the very last moment of a cohort and
    // contribute effectively in the following cohort
    rest_utils::token_check((*coordinator).clone(), token.as_str()).await?;

    let mut write_lock = (*coordinator).clone().write_owned().await;

    task::spawn_blocking(move || write_lock.add_to_queue(new_participant.participant, new_participant.ip_address, 10))
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))

    // FIXME: change state of token if all test passed
}

/// Lock a [Chunk](`crate::objects::Chunk`) in the ceremony. This should be the first function called when attempting to contribute to a chunk. Once the chunk is locked, it is ready to be downloaded.
#[get("/contributor/lock_chunk", format = "json")]
pub async fn lock_chunk(
    coordinator: &State<Coordinator>,
    participant: CurrentContributor,
) -> Result<Json<LockedLocators>> {
    let mut write_lock = (*coordinator).clone().write_owned().await;
    match task::spawn_blocking(move || write_lock.try_lock(&participant)).await? {
        Ok((_, locked_locators)) => Ok(Json(locked_locators)),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Get the challenge key on Amazon S3 from the [Coordinator](`crate::Coordinator`).
#[post("/contributor/challenge", format = "json", data = "<round_height>")]
pub async fn get_challenge_url(
    coordinator: &State<Coordinator>,
    _participant: CurrentContributor,
    round_height: LazyJson<u64>,
) -> Result<Json<String>> {
    let s3_ctx = S3Ctx::new().await?;
    let key = format!("round_{}/chunk_0/contribution_0.verified", *round_height);

    // If challenge is already on S3 (round rollback) immediately return the key
    if let Some(url) = s3_ctx.get_challenge_url(key.clone()).await {
        return Ok(Json(url));
    }

    // Since we don't chunk the parameters, we have one chunk and one allowed contributor per round. Thus the challenge will always be located at round_{i}/chunk_0/contribution_0.verified
    // For example, the 1st challenge (after the initialization) is located at round_1/chunk_0/contribution_0.verified
    let read_lock = (*coordinator).clone().read_owned().await;
    let challenge = match task::spawn_blocking(move || read_lock.get_challenge(*round_height, 0, 0, true)).await? {
        Ok(challenge) => challenge,
        Err(e) => return Err(ResponseError::CoordinatorError(e)),
    };

    // Upload challenge to S3 and return url
    let url = s3_ctx.upload_challenge(key, challenge).await?;

    Ok(Json(url))
}

/// Request the urls where to upload a [Chunk](`crate::objects::Chunk`) contribution and the ContributionFileSignature.
#[post("/upload/chunk", format = "json", data = "<round_height>")]
pub async fn get_contribution_url(
    _participant: CurrentContributor,
    round_height: LazyJson<u64>,
) -> Result<Json<(String, String)>> {
    let contrib_key = format!("round_{}/chunk_0/contribution_1.unverified", *round_height);
    let contrib_sig_key = format!("round_{}/chunk_0/contribution_1.unverified.signature", *round_height);

    // Prepare urls for the upload
    let s3_ctx = S3Ctx::new().await?;
    let urls = s3_ctx.get_contribution_urls(contrib_key, contrib_sig_key);

    Ok(Json(urls))
}

/// Notify the [Coordinator](`crate::Coordinator`) of a finished and uploaded [Contribution](`crate::objects::Contribution`). This will unlock the given [Chunk](`crate::objects::Chunk`).
#[post(
    "/contributor/contribute_chunk",
    format = "json",
    data = "<contribute_chunk_request>"
)]
pub async fn contribute_chunk(
    coordinator: &State<Coordinator>,
    participant: CurrentContributor,
    contribute_chunk_request: LazyJson<PostChunkRequest>,
) -> Result<()> {
    // Download contribution and its signature from S3 to local disk from the provided Urls
    let s3_ctx = S3Ctx::new().await?;
    let (contribution, contribution_sig) = s3_ctx.get_contribution(contribute_chunk_request.round_height).await?;
    let mut write_lock = (*coordinator).clone().write_owned().await;

    task::spawn_blocking(move || {
        write_lock.write_contribution(contribute_chunk_request.contribution_locator, contribution)?;
        write_lock.write_contribution_file_signature(
            contribute_chunk_request.contribution_signature_locator,
            serde_json::from_slice(&contribution_sig)?,
        )?;
        write_lock.try_contribute(&participant, 0) // Only 1 chunk per round, chunk_id is always 0
    })
    .await?
    .map_or_else(|e| Err(ResponseError::CoordinatorError(e)), |_| Ok(()))
}

/// Update the [Coordinator](`crate::Coordinator`) state. This endpoint is accessible only by the coordinator itself.
#[cfg(debug_assertions)]
#[get("/update")]
pub async fn update_coordinator(coordinator: &State<Coordinator>, _auth: ServerAuth) -> Result<()> {
    rest_utils::perform_coordinator_update((*coordinator).clone()).await
}

/// Let the [Coordinator](`crate::Coordinator`) know that the participant is still alive and participating (or waiting to participate) in the ceremony.
#[post("/contributor/heartbeat")]
pub async fn heartbeat(coordinator: &State<Coordinator>, participant: Participant) -> Result<()> {
    coordinator
        .write()
        .await
        .heartbeat(&participant)
        .map_err(|e| ResponseError::CoordinatorError(e))
}

/// Stop the [Coordinator](`crate::Coordinator`) and shuts the rest server down. This endpoint is accessible only by the coordinator itself.
#[get("/stop")]
pub async fn stop_coordinator(_auth: ServerAuth, shutdown: Shutdown) {
    // Shut Rocket server down
    shutdown.notify();
}

/// Verify all the pending contributions. This endpoint is accessible only by the coordinator itself.
#[cfg(debug_assertions)]
#[get("/verify")]
pub async fn verify_chunks(coordinator: &State<Coordinator>, _auth: ServerAuth) -> Result<()> {
    rest_utils::perform_verify_chunks((*coordinator).clone()).await
}

/// Load new tokens to update the future cohorts. The `tokens` parameter is the serialized zip folder
#[post("/update_cohorts", format = "json", data = "<tokens>")]
pub async fn update_cohorts(
    coordinator: &State<Coordinator>,
    _auth: ServerAuth,
    tokens: LazyJson<Vec<u8>>,
) -> Result<()> {
    let reader = Cursor::new(tokens.clone());
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| ResponseError::IoError(e.to_string()))?;
    let mut zip_clone = zip.clone();

    let new_tokens = task::spawn_blocking(move || -> Result<Vec<HashMap<String, (Participant, TokenState)>>> {
        let mut cohorts: HashMap<String, Vec<u8>> = HashMap::new();
        let file_names: Vec<String> = zip_clone.file_names().map(|name| name.to_owned()).collect();

        for file in file_names {
            let mut buffer = Vec::new();
            zip_clone
                .by_name(file.as_str())
                .map_err(|e| ResponseError::IoError(e.to_string()))?
                .read_to_end(&mut buffer)
                .map_err(|e| ResponseError::IoError(e.to_string()))?;
            cohorts.insert(file, buffer);
        }

        // FIXME: copy the previous token states to the new tokens here or in load_tokens_from_bytes
        Ok(CoordinatorState::load_tokens_from_bytes(&cohorts))
    })
    .await
    .unwrap()?;

    // Check that the new tokens for the current cohort match the old ones (to prevent inconsistencies during contributions in the current cohort)
    let read_lock = coordinator.read().await;
    let cohort = read_lock.state().get_current_cohort_index();
    let old_tokens = match read_lock.state().tokens(cohort) {
        Some(t) => t,
        None => return Err(ResponseError::CeremonyIsOver),
    };

    match new_tokens.get(cohort) {
        Some(new_tokens) => {
            if new_tokens != old_tokens {
                return Err(ResponseError::InvalidNewTokens)
            }
        },
        _ => return Err(ResponseError::InvalidNewTokens),
    }
    drop(read_lock);

    // Persist new tokens to disk
    // New tokens MUST be written to file in case of a coordinator restart
    task::spawn_blocking(move || -> Result<()> {
        let mut zip_file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(TOKENS_ZIP_FILE)
            .map_err(|e| ResponseError::IoError(e.to_string()))?;

        zip_file
            .write_all(&tokens)
            .map_err(|e| ResponseError::IoError(e.to_string()))?;

        if let Err(e) = std::fs::remove_dir_all(&*TOKENS_PATH) {
            // Log the error and continue
            warn!("Error while removing old tokens folder: {}", e);
        }
        zip.extract(&*TOKENS_PATH)
            .map_err(|e| ResponseError::IoError(e.to_string()))?;

        Ok(())
    })
    .await
    .unwrap()?;

    // Update cohorts in coordinator's state
    coordinator.write().await.update_tokens(new_tokens);

    Ok(())
}

/// Get the queue status of the contributor.
#[get("/contributor/queue_status", format = "json")]
pub async fn get_contributor_queue_status(
    coordinator: &State<Coordinator>,
    participant: Participant,
) -> Json<ContributorStatus> {
    let contributor = participant.clone();

    let read_lock = (*coordinator).clone().read_owned().await;
    // Check that the contributor is authorized to lock a chunk in the current round.
    if task::spawn_blocking(move || read_lock.is_current_contributor(&contributor))
        .await
        .unwrap()
    {
        return Json(ContributorStatus::Round);
    }

    let read_lock = coordinator.read().await;

    if read_lock.is_queue_contributor(&participant) {
        let queue_size = read_lock.number_of_queue_contributors() as u64;

        let queue_position = match read_lock.state().queue_contributor_info(&participant) {
            Some((_, Some(round), _, _)) => round - read_lock.state().current_round_height(),
            Some((_, None, _, _)) => queue_size,
            None => return Json(ContributorStatus::Other),
        };

        return Json(ContributorStatus::Queue(queue_position, queue_size));
    }

    if read_lock.is_finished_contributor(&participant) {
        return Json(ContributorStatus::Finished);
    }

    if read_lock.is_banned_participant(&participant) {
        return Json(ContributorStatus::Banned);
    }

    // Not in the queue, not finished, nor in the current round
    Json(ContributorStatus::Other)
}

/// Write [`ContributionInfo`] to disk
#[post("/contributor/contribution_info", format = "json", data = "<request>")]
pub async fn post_contribution_info(
    coordinator: &State<Coordinator>,
    participant: CurrentContributor,
    request: LazyJson<ContributionInfo>,
) -> Result<()> {
    // Validate info
    if request.public_key != participant.address() {
        return Err(ResponseError::InvalidContributionInfo(format!(
            "Public key in info {} doesnt' match the participant one {}",
            request.public_key,
            participant.address()
        )));
    }

    let current_round_height = match coordinator.read().await.current_round_height() {
        Ok(r) => r,
        Err(e) => return Err(ResponseError::CoordinatorError(e)),
    };

    if current_round_height != request.ceremony_round {
        // NOTE: validation of round_height matters in case of a round rollback
        return Err(ResponseError::InvalidContributionInfo(format!(
            "Round height in info {} doesnt' match the current round height {}",
            request.ceremony_round, current_round_height
        )));
    }

    // Write contribution info and summary to file
    let mut write_lock = (*coordinator).clone().write_owned().await;

    task::spawn_blocking(move || {
        write_lock.write_contribution_info(request.clone())?;

        write_lock.update_contribution_summary(request.0.into())
    })
    .await?
    .map_err(|e| ResponseError::CoordinatorError(e))
}

/// Retrieve the contributions' info. This endpoint is accessible by anyone and does not require a signed request.
#[get("/contribution_info")]
pub async fn get_contributions_info(coordinator: &State<Coordinator>) -> Result<Vec<u8>> {
    let read_lock = (*coordinator).clone().read_owned().await;
    let summary = task::spawn_blocking(move || read_lock.storage().get_contributions_summary())
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?;

    Ok(summary)
}

/// Retrieve the coordinator.json status file
#[get("/coordinator_status")]
pub async fn get_coordinator_state(coordinator: &State<Coordinator>, _auth: Secret) -> Result<Vec<u8>> {
    let read_lock = (*coordinator).clone().read_owned().await;
    let state = task::spawn_blocking(move || read_lock.storage().get_coordinator_state())
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?;

    Ok(state)
}

/// Retrieve healthcheck info. This endpoint is accessible by anyone and does not require a signed request.
#[get("/healthcheck", format = "json")]
pub async fn get_healthcheck() -> Result<String> {
    let content = fs::read_to_string(HEALTH_PATH.as_str())
        .await
        .map_err(|e| ResponseError::IoError(e.to_string()))?;

    Ok(content)
}
