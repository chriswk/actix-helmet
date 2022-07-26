//! For middleware documentation, see [`DefaultHeaders`].

use std::rc::Rc;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use actix_service::Transform;

use actix_web::{
    body::{MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse},
    Error, Result,
};
use actix_web::http::header;
use actix_web::http::header::{HeaderValue, TryIntoHeaderPair};
use futures_core::ready;
use futures_util::future::{FutureExt as _, Ready, ready};
use log::debug;
use pin_project_lite::pin_project;


/// Middleware for setting default response headers.
///
/// Headers with the same key that are already set in a response will *not* be overwritten.
///
/// # Examples
/// ```
/// use actix_web::{web, http, middleware, App, HttpResponse};
///
/// let app = App::new()
///     .wrap(actix_helmet::middleware::helmet::Helmet::default())
///     .service(
///         web::resource("/test")
///             .route(web::get().to(|| HttpResponse::Ok()))
///             .route(web::method(http::Method::HEAD).to(|| HttpResponse::MethodNotAllowed()))
///     );
/// ```
#[derive(Debug, Clone, Default)]
pub struct Helmet {
    inner: Rc<Inner>,
}

pub struct Headers {
    content_security_policy: ContentSecurityPolicyOptions
}

#[derive(Debug, Clone)]
pub struct ContentSecurityPolicyOptions {
    default_src: Vec<String>,
    base_uri: Vec<String>,
    block_all_mixed_content: bool,
    font_src: Vec<String>,
    form_action: Vec<String>,
    frame_ancestors: Vec<String>,
    img_src: Vec<String>,
    object_src: Vec<String>,
    script_src: Vec<String>,
    script_src_attr: Vec<String>,
    style_src: Vec<String>,
    upgrade_insecure_requests: bool
}

const SELF_SOURCE: &str = "'self'";
const HTTPS_SOURCE: &str = "https:";
const DATA_SOURCE: &str = "data:";
const NONE_SOURCE: &str = "'self'";
const UNSAFE_INLINE: &str = "'unsafe-inline'";
const SRC_JOINER: &str = " ";

impl Default for ContentSecurityPolicyOptions {
    fn default() -> Self {
        ContentSecurityPolicyOptions {
            default_src: vec![SELF_SOURCE.to_string()],
            base_uri: vec![SELF_SOURCE.to_string()],
            block_all_mixed_content: true,
            font_src: vec![SELF_SOURCE.to_string(), HTTPS_SOURCE.to_string(), DATA_SOURCE.to_string()],
            form_action: vec![SELF_SOURCE.to_string()],
            frame_ancestors: vec![SELF_SOURCE.to_string()],
            img_src: vec![SELF_SOURCE.to_string(), DATA_SOURCE.to_string()],
            object_src: vec![NONE_SOURCE.to_string()],
            script_src: vec![SELF_SOURCE.to_string()],
            script_src_attr: vec![NONE_SOURCE.to_string()],
            style_src: vec![SELF_SOURCE.to_string(), HTTPS_SOURCE.to_string(), UNSAFE_INLINE.to_string()],
            upgrade_insecure_requests: true
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    content_security_options: ContentSecurityPolicyOptions,
}

impl Helmet {
    /// Constructs an empty `Helmet` middleware.
    #[inline]
    pub fn new() -> Helmet {
        Helmet::default()
    }

}

impl<S, B> Transform<S, ServiceRequest> for Helmet
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
        S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = HelmetMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(HelmetMiddleware {
            service,
            inner: Rc::clone(&self.inner),
        }))
    }
}

pub struct HelmetMiddleware<S> {
    service: S,
    inner: Rc<Inner>,
}

impl<S, B> Service<ServiceRequest> for HelmetMiddleware<S>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
        S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = HelmetFuture<S, B>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner = self.inner.clone();
        let fut = self.service.call(req);

        HelmetFuture {
            fut,
            inner,
            _body: PhantomData,
        }
    }
}

pin_project! {
    pub struct HelmetFuture<S: Service<ServiceRequest>, B> {
        #[pin]
        fut: S::Future,
        inner: Rc<Inner>,
        _body: PhantomData<B>,
    }
}

impl<S, B> Future for HelmetFuture<S, B>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Output = <S::Future as Future>::Output;

    #[allow(clippy::borrow_interior_mutable_const)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut res = ready!(this.fut.poll(cx))?;

        // Only set CSP if not already set
        if !res.headers().contains_key(header::CONTENT_SECURITY_POLICY) {
            let block_content = if this.inner.content_security_options.block_all_mixed_content {
                "block-all-mixed-content"
            } else {
                ""
            };
            let upgrade_insecure = if this.inner.content_security_options.upgrade_insecure_requests {
                "upgrade-insecure-requests"
            } else {
                ""
            };
            let header_string: String = format!(r#"default-src {};base-uri {};{};font-src {}; form-action {};frame-ancestors {};img-src {};object-src {};script-src {};script-src-attr {};style-src {};{}"#,
                                                this.inner.content_security_options.default_src.join(" "),
                                                this.inner.content_security_options.base_uri.join(" "),
                                                block_content,
                                                this.inner.content_security_options.font_src.join(" "),
                                                this.inner.content_security_options.form_action.join(" "),
                                                this.inner.content_security_options.frame_ancestors.join(" "),
                                                this.inner.content_security_options.img_src.join(" "),
                                                this.inner.content_security_options.object_src.join(" "),
                                                this.inner.content_security_options.script_src.join(" "),
                                                this.inner.content_security_options.script_src_attr.join(" "),
                                                this.inner.content_security_options.style_src.join(" "),
                                                upgrade_insecure,
            );
            match HeaderValue::from_bytes(header_string.as_bytes()) {
                Ok(header_value) => {
                    res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, header_value);
                }
                _ => ()
            };
        }

        Poll::Ready(Ok(res))
    }
}

#[cfg(test)]
mod tests {
    use actix_service::{IntoService, Service, Transform};
    use actix_web::test;
    use actix_web::test::TestRequest;
    use crate::middleware::helmet::Helmet;

    #[actix_web::test]
    async fn adding_default_headers() {
        let mw = Helmet::new()
            .new_transform(test::ok_service())
            .await
            .unwrap();

        let req = TestRequest::default().to_srv_request();
        let res = mw.call(req).await.unwrap();
        assert_eq!(res.headers().get("Content-Security-Policy").unwrap(), r#"default-src 'self';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests"#);
    }
}
