//! OpenAPI spec serving and Swagger UI endpoints.
//!
//! - `GET /v1/openapi.yaml` — raw OpenAPI 3.1 spec
//! - `GET /v1/docs` — Swagger UI (CDN-hosted, no extra dependencies)

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};

/// The OpenAPI 3.1 spec, embedded at compile time.
const OPENAPI_YAML: &str = include_str!("../../openapi.yaml");

/// GET /v1/openapi.yaml — serves the raw OpenAPI spec.
pub async fn openapi_yaml() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/yaml; charset=utf-8")],
        OPENAPI_YAML,
    )
}

/// GET /v1/docs — serves Swagger UI pointing at the embedded spec.
pub async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_HTML)
}

const SWAGGER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lago API — Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "./openapi.yaml",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset,
      ],
      layout: "BaseLayout",
    });
  </script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_yaml_is_valid() {
        // Verify the embedded spec is valid YAML and has the expected structure
        let value: serde_yaml::Value =
            serde_yaml::from_str(OPENAPI_YAML).expect("embedded openapi.yaml must be valid YAML");
        let map = value.as_mapping().expect("root must be a mapping");

        // Check required top-level keys
        let openapi = map
            .get(serde_yaml::Value::String("openapi".into()))
            .expect("must have 'openapi' key");
        assert_eq!(openapi.as_str().unwrap(), "3.1.0");

        assert!(map
            .get(serde_yaml::Value::String("info".into()))
            .is_some());
        assert!(map
            .get(serde_yaml::Value::String("paths".into()))
            .is_some());
        assert!(map
            .get(serde_yaml::Value::String("components".into()))
            .is_some());
    }
}
