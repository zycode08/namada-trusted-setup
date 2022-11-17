use lazy_static::lazy_static;
use rocket::tokio::io::AsyncReadExt;
use rusoto_core::{region::Region, request::TlsError};
use rusoto_credential::{AwsCredentials, ChainProvider, CredentialsError, ProvideAwsCredentials};
use rusoto_s3::{
    util::{PreSignedRequest, PreSignedRequestOption},
    DeleteObjectRequest,
    GetObjectRequest,
    HeadObjectRequest,
    PutObjectRequest,
    S3Client,
    StreamingBody,
    S3,
};
use std::str::FromStr;
use thiserror::Error;

pub const TOKENS_ZIP_FILE: &str = "tokens.zip";

lazy_static! {
    static ref BUCKET: String = std::env::var("AWS_S3_BUCKET").unwrap_or("bucket".to_string());
    pub static ref REGION: Region = {
        match std::env::var("AWS_REGION") {
            Ok(region) => Region::from_str(&region).expect("Region must be a valid region"),
            Err(_) => Region::EuWest1,
        }
    };
    static ref S3_REGION: Region = Region::Custom {
        name: REGION.name().to_string(),
        endpoint: format!("{}.s3-accelerate.amazonaws.com", *BUCKET),
    };
}

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
    UploadError(String),
}

type Result<T> = std::result::Result<T, S3Error>;

pub struct S3Ctx {
    client: S3Client,
    bucket: &'static String,
    region: &'static Region,
    options: PreSignedRequestOption,
    credentials: AwsCredentials,
}

impl S3Ctx {
    pub async fn new() -> Result<Self> {
        let provider = ChainProvider::new();
        let credentials = provider.credentials().await?;
        let client = S3Client::new(S3_REGION.clone());
        let options = PreSignedRequestOption {
            expires_in: std::time::Duration::from_secs(600),
        };

        Ok(Self {
            client,
            bucket: &BUCKET,
            region: &S3_REGION,
            options,
            credentials,
        })
    }

    /// Upload contributors.json file to S3 for the frontend
    pub(crate) async fn upload_contributions_info(&self, contributions_info: Vec<u8>) -> Result<()> {
        // First delete the old file to allow triggering the lambda
        let delete_object_request = DeleteObjectRequest {
            bucket: self.bucket.clone(),
            key: "contributors.json".to_string(),
            ..Default::default()
        };

        self.client
            .delete_object(delete_object_request)
            .await
            .map_or_else(|e| Err(S3Error::UploadError(e.to_string())), |_| Ok(()))?;

        // Upload the updated file
        let put_object_request = PutObjectRequest {
            bucket: self.bucket.clone(),
            key: "contributors.json".to_string(),
            body: Some(StreamingBody::from(contributions_info)),
            ..Default::default()
        };

        self.client
            .put_object(put_object_request)
            .await
            .map_or_else(|e| Err(S3Error::UploadError(e.to_string())), |_| Ok(()))
    }

    /// Get the url of a challenge on S3.
    pub async fn get_challenge_url(&self, key: String) -> Option<String> {
        let head = HeadObjectRequest {
            bucket: self.bucket.clone(),
            key: key.clone(),
            ..Default::default()
        };

        if self.client.head_object(head).await.is_ok() {
            let get = GetObjectRequest {
                bucket: self.bucket.clone(),
                key,
                ..Default::default()
            };

            Some(get.get_presigned_url(self.region, &self.credentials, &self.options))
        } else {
            None
        }
    }

    /// Upload a challenge to S3. Returns the presigned url to get it.
    pub async fn upload_challenge(&self, key: String, challenge: Vec<u8>) -> Result<String> {
        let put_object_request = PutObjectRequest {
            bucket: self.bucket.clone(),
            key: key.clone(),
            body: Some(StreamingBody::from(challenge)),
            ..Default::default()
        };

        self.client
            .put_object(put_object_request)
            .await
            .map_err(|e| S3Error::UploadError(e.to_string()))?;

        let get = GetObjectRequest {
            bucket: self.bucket.clone(),
            key,
            ..Default::default()
        };

        Ok(get.get_presigned_url(self.region, &self.credentials, &self.options))
    }

    /// Get the urls of a contribution and its signature.
    pub(crate) fn get_contribution_urls(&self, contrib_key: String, contrib_sig_key: String) -> (String, String) {
        let get_contrib = PutObjectRequest {
            bucket: self.bucket.clone(),
            key: contrib_key,
            ..Default::default()
        };
        let get_sig = PutObjectRequest {
            bucket: self.bucket.clone(),
            key: contrib_sig_key,
            ..Default::default()
        };

        // NOTE: urls live for 5 minutes so we cannot cache them for reuse because there's a high chance they expired, we
        //  need to regenerate them every time
        let contrib_url = get_contrib.get_presigned_url(self.region, &self.credentials, &self.options);
        let contrib_sig_url = get_sig.get_presigned_url(self.region, &self.credentials, &self.options);

        (contrib_url, contrib_sig_url)
    }

    /// Download an object from S3 as bytes.
    async fn get_object(&self, get_request: GetObjectRequest) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let stream = self
            .client
            .get_object(get_request)
            .await
            .map_err(|e| S3Error::DownloadError(e.to_string()))?
            .body
            .ok_or(S3Error::EmptyContribution)?;
        stream.into_async_read().read_to_end(&mut buffer).await?;

        Ok(buffer)
    }

    /// Retrieve a contribution and its signature from S3.
    pub(crate) async fn get_contribution(&self, round_height: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let get_contrib = GetObjectRequest {
            bucket: self.bucket.clone(),
            key: format!("round_{}/chunk_0/contribution_1.unverified", round_height),
            ..Default::default()
        };
        let get_sig = GetObjectRequest {
            bucket: self.bucket.clone(),
            key: format!("round_{}/chunk_0/contribution_1.unverified.signature", round_height),
            ..Default::default()
        };

        rocket::tokio::try_join!(self.get_object(get_contrib), self.get_object(get_sig))
    }

    /// Retrieve the compressed token folder.
    pub async fn get_tokens(&self) -> Result<Vec<u8>> {
        let key = match std::env::var("AWS_S3_PROD") {
            Ok(t) if t == "true" => format!("prod/{}", TOKENS_ZIP_FILE),
            _ => format!("master/{}", TOKENS_ZIP_FILE),
        };

        let get_tokens = GetObjectRequest {
            bucket: self.bucket.clone(),
            key,
            ..Default::default()
        };

        self.get_object(get_tokens).await
    }
}
