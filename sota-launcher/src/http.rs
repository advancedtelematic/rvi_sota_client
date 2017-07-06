use datatypes::PlayCookie;


header! { (CsrfToken, "Csrf-Token") => [String] }
header! { (Cookie, "Cookie") => [PlayCookie] }
