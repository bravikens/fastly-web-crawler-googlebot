use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use serde_json::Value;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// The name of a backend server associated with this service.
/// When configuring the backend using Fastly's UI, make sure it points to "dns.google.com".
const DNS_RESOLVER: &str = "origin_0";

/// The outcome of a lookup request.
enum Outcome {
    /// The client request had no query string.
    MissingQueryString,
    /// The client request had an invalid query string.
    InvalidQueryString,
    /// Google DNS failed.
    GoogleDnsFailed,
    /// The client request came from a googlebot.
    IsGoogleBot { ptr_record: String },
    /// The client request did not come from a googlebot.
    NotGoogleBot { ptr_record: String },
    /// No PTR Answer was found.
    NoPtrAnswer,
}

/// Convert a lookup request's [`Outcome`] into an HTTP [`Response`].
impl From<Outcome> for Response {
    fn from(outcome: Outcome) -> Self {
        use Outcome::*;
        let (result, reason, status) = match outcome {
            MissingQueryString => (
                "error",
                "Missing query string ?ip=a.b.c.d".to_string(),
                StatusCode::BAD_REQUEST,
            ),
            InvalidQueryString => (
                "error",
                "Invalid query string ?ip=a.b.c.d".to_string(),
                StatusCode::BAD_REQUEST,
            ),
            GoogleDnsFailed => (
                "error",
                "Google DNS failed".to_string(),
                StatusCode::BAD_GATEWAY,
            ),
            IsGoogleBot { ptr_record } => (
                "yes",
                format!("Reverse lookup is {}", ptr_record),
                StatusCode::OK,
            ),
            NotGoogleBot { ptr_record } => (
                "no",
                format!(
                    "Reverse lookup is {}, not an *.google.com or *.googlebot.com domain.",
                    ptr_record
                ),
                StatusCode::OK,
            ),
            NoPtrAnswer => (
                "no",
                "No PTR Answer for this reverse lookup.".to_string(),
                StatusCode::OK,
            ),
        };
        let body_json = serde_json::json!({
            "result": result,
            "reason": reason,
        });

        Response::from_status(status)
            .with_header(header::CONTENT_TYPE, "application/json")
            .with_header("x-googlebot-verified", result)
            .with_body_json(&body_json)
            .unwrap()
    }
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Pattern match on the request method and path.
    match (req.get_method(), req.get_path()) {
        (&Method::GET, "/verify") => match handle_lookup_request(req) {
            Ok(response) => Ok(response),
            Err(error) => Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain(&format!("ERROR: {}", error))),
        },

        // Catch all other requests and return a 404.
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND).with_body(
            "Either the page you requested could not be found or the HTTP method is not GET.\n",
        )),
    }
}

fn handle_lookup_request(req: Request) -> Result<Response, Error> {
    // extract the ip address from query string ?ip=value
    let qs_params: HashMap<String, String> = req.get_query()?;

    let ip = match qs_params.get("ip") {
        Some(ip) => ip,
        // handle missing param
        _ => {
            return Ok(Outcome::MissingQueryString.into());
        }
    };

    match ip.parse::<Ipv4Addr>() {
        Ok(ipv4) => {
            let ipv4_octets = ipv4.octets();
            let uri = format!(
                "https://dns.google.com/resolve?name={}.{}.{}.{}.in-addr.arpa&type=PTR",
                ipv4_octets[3], ipv4_octets[2], ipv4_octets[1], ipv4_octets[0],
            );

            let dns_request = Request::get(uri);

            let mut beresp = dns_request.send(DNS_RESOLVER)?;
            if !beresp.get_status().is_success() {
                return Ok(Outcome::GoogleDnsFailed.into());
            }

            let beresp_body = beresp.take_body_str();
            let dns_data: Value = serde_json::from_str(&beresp_body).unwrap();
            let ptr_record = &dns_data["Answer"][0]["data"].as_str();

            let is_googlebot_decision = match ptr_record {
                Some(domain)
                    if domain.ends_with(".google.com.") || domain.ends_with(".googlebot.com.") =>
                {
                    Outcome::IsGoogleBot {
                        ptr_record: domain.to_string(),
                    }
                }
                Some(domain) => Outcome::NotGoogleBot {
                    ptr_record: domain.to_string(),
                },

                _ => Outcome::NoPtrAnswer,
            };

            Ok(is_googlebot_decision.into())
        }
        _ => Ok(Outcome::InvalidQueryString.into()),
    }
}
