create TABLE IF NOT EXISTS requests
(
    request_id  	BIGSERIAL PRIMARY KEY,
    method 			TEXT 	  NOT NULL,
    path 			TEXT 	  NOT NULL,
    query_params 	JSONB 	  NOT NULL,
    headers 		JSONB 	  NOT NULL,
    cookies 		JSONB 	  NOT NULL,
    content_type 	TEXT 	  NOT NULL,
    body        	text 	  NOT NULL
);

CREATE TABLE IF NOT EXISTS responses
(
    response_id  BIGSERIAL  PRIMARY KEY,
    status_code  INT 	    NOT NULL,
    message 	 TEXT 	    NOT NULL,
    headers 	 JSONB 	    NOT NULL,
    content_type TEXT 	  	NOT NULL,
    body         TEXT 	    NOT NULL,
    request_id   BIGINT 	NOT NULL,

    CONSTRAINT fk_responses_request_id FOREIGN KEY (request_id)
    REFERENCES requests ON DELETE CASCADE
    );