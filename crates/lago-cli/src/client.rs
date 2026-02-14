use lago_api::routes::sessions::{CreateSessionRequest, CreateSessionResponse, SessionResponse};
use reqwest::StatusCode;

pub struct Client {
    base_url: String,
    client: reqwest::Client,
}

impl Client {
    pub fn new(http_port: u16) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{}", http_port),
            client: reqwest::Client::new(),
        }
    }

    /// Check if the server is healthy/reachable.
    pub async fn health(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        // println!("Checking health at: {}", url);
        match self.client.get(&url).send().await {
            Ok(res) => {
                // println!("Health check status: {}", res.status());
                res.status().is_success()
            }
            Err(_e) => {
                // println!("Health check failed: {}", e);
                false
            }
        }
    }

    pub async fn create_session(&self, name: &str) -> Result<CreateSessionResponse, String> {
        let req = CreateSessionRequest {
            name: name.to_string(),
            model: None,
            params: None,
        };

        let res = self
            .client
            .post(format!("{}/v1/sessions", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if res.status() == StatusCode::CREATED {
            res.json::<CreateSessionResponse>()
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("server error: {}", res.status()))
        }
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionResponse>, String> {
        let res = self
            .client
            .get(format!("{}/v1/sessions", self.base_url))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            res.json::<Vec<SessionResponse>>()
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("server error: {}", res.status()))
        }
    }

    pub async fn get_session(&self, id: &str) -> Result<SessionResponse, String> {
        let res = self
            .client
            .get(format!("{}/v1/sessions/{}", self.base_url, id))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            res.json::<SessionResponse>()
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("server error: {}", res.status()))
        }
    }
}
