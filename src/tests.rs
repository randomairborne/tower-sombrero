use axum::{routing::get, Router};
use tokio::{net::TcpListener, sync::oneshot::Sender, task::JoinHandle};

use crate::{
    headers::{ContentSecurityPolicy, CspSource},
    Sombrero,
};

#[tokio::test]
async fn sombrero_layer_compiles() {
    let sombrero = Sombrero::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = Router::new().route("/", get(test_handler)).layer(sombrero);
    axum::serve(listener, app)
        .with_graceful_shutdown(std::future::ready(()))
        .await
        .unwrap()
}

#[tokio::test]
async fn sombrero_layer_handles() {
    let sombrero = Sombrero::default();
    let server = test_server(sombrero).await;
    reqwest::get(server.url())
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn sombrero_layer_adds_csp() {
    let sombrero = Sombrero::default();
    let server = test_server(sombrero).await;
    let resp = reqwest::get(server.url()).await.unwrap();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    eprintln!("{csp}");
    assert!(csp.contains("default-src 'self';"));
    assert!(csp.contains("base-uri 'self';"));
    server.shutdown().await;
}

#[tokio::test]
async fn sombrero_layer_changes_csp_nonce() {
    let csp = ContentSecurityPolicy::new().script_src([CspSource::Nonce]);
    let sombrero = Sombrero::new().content_security_policy(csp);
    let server = test_server(sombrero).await;
    let resp1 = reqwest::get(server.url()).await.unwrap();
    let resp2 = reqwest::get(server.url()).await.unwrap();
    let nonce1 = helper_get_nonce(&resp1, "content-security-policy");
    let nonce2 = helper_get_nonce(&resp2, "content-security-policy");
    assert_ne!(nonce1, nonce2);
    server.shutdown().await;
}

#[tokio::test]
async fn sombrero_layer_one_nonce_per_request() {
    let csp = ContentSecurityPolicy::new().script_src([CspSource::Nonce]);
    let sombrero = Sombrero::new()
        .content_security_policy(csp.clone())
        .content_security_policy_report_only(csp);
    let server = test_server(sombrero).await;
    let resp = reqwest::get(server.url()).await.unwrap();
    let nonce_ac = helper_get_nonce(&resp, "content-security-policy");
    let nonce_ro = helper_get_nonce(&resp, "content-security-policy-report-only");
    assert_eq!(nonce_ac, nonce_ro);
    server.shutdown().await;
}

fn helper_get_nonce(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .unwrap()
        .to_str()
        .unwrap()
        .trim_start_matches("script-src 'nonce-")
        .trim_end_matches("';")
        .to_string()
}

async fn test_server(sombrero: Sombrero) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = Router::new().route("/", get(test_handler)).layer(sombrero);
    let port = listener.local_addr().unwrap().port();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                shutdown_rx.await.unwrap();
            })
            .await
            .unwrap()
    });
    Server {
        port,
        shutdown_tx,
        task,
    }
}

struct Server {
    port: u16,
    shutdown_tx: Sender<()>,
    task: JoinHandle<()>,
}

impl Server {
    async fn shutdown(self) {
        self.shutdown_tx.send(()).unwrap();
        self.task.await.unwrap();
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }
}

async fn test_handler() -> &'static str {
    "Test Handler!"
}
