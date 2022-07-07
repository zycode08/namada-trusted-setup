use rusoto_credential::{ChainProvider, ProvideAwsCredentials, AwsCredentials, CredentialsError};
use rusoto_core::{region::Region, HttpClient, request::TlsError, RusotoError};
use rusoto_s3::{GetObjectRequest, PutObjectRequest, util::{PreSignedRequestOption, PreSignedRequest}, S3, S3Client, CreateMultipartUploadRequest, StreamingBody, HeadObjectRequest};
use thiserror::Error;
use rocket::tokio::io::AsyncReadExt;

const BUCKET: &str = "bucket";

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("Error while creating the http client: {0}")]
    Client(#[from] TlsError),
    #[error("Error while generating S3 credentials: {0}")]
    Credentials(#[from] CredentialsError),
    #[error("Download of S3 file failed: {0}")]
    DownloadError(String),
    #[error("S3 contribution file is present but empty")]
    EmptyContribution,
    #[error("S3 contribution file signature is present but empty")]
    EmptyContributionSignature,
    #[error("Error in IO: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Upload of challenge to S3 failed: {0}")]
    UploadError(String)
}

type Result<T> = std::result::Result<T, S3Error>;

pub(crate) struct S3Ctx {
    client: S3Client,
    region: Region,
    options: PreSignedRequestOption,
    credentials: AwsCredentials
}

pub(crate) async fn get_s3_ctx() -> Result<S3Ctx> {
    let provider = ChainProvider::new();
    let region = Region::Custom {
        name: "custom".to_string(),
        endpoint: "http://localhost:4566".to_string(), //FIXME: manage production release
    };
    let credentials = provider.credentials().await?;
    let client = S3Client::new_with(HttpClient::new()?, provider, region.clone());
    let options = PreSignedRequestOption {
        expires_in: std::time::Duration::from_secs(300),
    };
    
    Ok(S3Ctx {
        client,
        region,
        options,
        credentials
    })
}

pub(crate) async fn get_challenge_url(ctx: &S3Ctx, key: String) -> Option<String> {
    let head = HeadObjectRequest {
        bucket: BUCKET.to_string(),
        key: key.clone(),
        ..Default::default()
    };

    if ctx.client.head_object(head).await.is_ok() {
        let get = GetObjectRequest {
            bucket: BUCKET.to_string(),
            key,
            ..Default::default()
        };

        Some(get.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options))
    } else {
        None
    }
}

pub(crate) async fn upload_challenge(ctx: &S3Ctx, key: String, challenge: Vec<u8>) -> Result<String> {
    let put_object_request = PutObjectRequest {
        bucket: BUCKET.to_string(),
        key: key.clone(),
        body: Some(StreamingBody::from(challenge)),
        ..Default::default()
    };
    
    let upload_result = ctx.client.put_object(put_object_request).await.map_err(|e| S3Error::UploadError(e.to_string()))?;

    let get = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key,
        ..Default::default()
    };

    Ok(get.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options))
}

pub(crate) fn get_contribution_urls(ctx: &S3Ctx, contrib_key: String, contrib_sig_key: String) -> (String, String) {
    let get_contrib = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: contrib_key,
        ..Default::default()
    };
    let get_sig = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: contrib_sig_key,
        ..Default::default()
    };

    let contrib_url = get_contrib.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options);
    let contrib_sig_url = get_sig.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options);

    (contrib_url, contrib_sig_url)
}

pub(crate) async fn get_contribution(ctx: &S3Ctx, round_height: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    let get_contrib = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: format!("round_{}/chunk_0/contribution_1.unverified", round_height),
        ..Default::default()
    };
    let get_sig = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: format!("round_{}/chunk_0/contribution_1.unverified.signature", round_height),
        ..Default::default()
    };

    // FIXME: join in parallel? Or at least for loop to reduce code duplication
    let contribution_stream = ctx.client.get_object(get_contrib).await.map_err(|e| S3Error::DownloadError(e.to_string()))?.body.ok_or(S3Error::EmptyContribution)?;
    let mut contribution = Vec::new();
    contribution_stream.into_async_read().read_to_end(&mut contribution).await?;

    let contribution_sig_stream = ctx.client.get_object(get_sig).await.map_err(|e| S3Error::DownloadError(e.to_string()))?.body.ok_or(S3Error::EmptyContribution)?;
    let mut contribution_sig = Vec::new();
    contribution_sig_stream.into_async_read().read_to_end(&mut contribution_sig).await?;

    Ok((contribution, contribution_sig))
}