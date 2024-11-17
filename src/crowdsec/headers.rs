use axum::http::HeaderName;

pub const X_CROWDSEC_APPSEC_IP_HEADER: HeaderName = HeaderName::from_static("x-crowdsec-appsec-ip");
pub const X_CROWDSEC_APPSEC_URI_HEADER: HeaderName =
    HeaderName::from_static("x-crowdsec-appsec-uri");
pub const X_CROWDSEC_APPSEC_HOST_HEADER: HeaderName =
    HeaderName::from_static("x-crowdsec-appsec-host");
pub const X_CROWDSEC_APPSEC_VERB_HEADER: HeaderName =
    HeaderName::from_static("x-crowdsec-appsec-verb");
pub const X_CROWDSEC_APPSEC_API_KEY_HEADER: HeaderName =
    HeaderName::from_static("x-crowdsec-appsec-api-key");
pub const X_CROWDSEC_APPSEC_USER_AGENT_HEADER: HeaderName =
    HeaderName::from_static("x-crowdsec-appsec-user-agent");
