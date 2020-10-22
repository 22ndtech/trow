use crate::registry_interface::manifest::Manifest;
use rocket::request::Request;
use rocket::http::ContentType;
use rocket::http::Status;
use rocket::response::{Responder, Response, self};
use std::io::Cursor;

impl<'r> Responder<'r> for Manifest {
    fn respond_to(self, req: &Request) -> response::Result<'r> {

        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(self.to_json_blocking()))
            .status(Status::Ok)
            .ok()
    }
}
