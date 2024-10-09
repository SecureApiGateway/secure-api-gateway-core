/**
 * This script is a simple implementation of HTTP Basic Authentication on
 * server side.
 * It expects the following arguments:
 *  - realm: the realm to display when the user-agent prompts for
 *    username and password if none were provided.
 *  - username: the expected username
 *  - password: the expected password
 */
SCRIPT_NAME = "[ErrorResponseFilter] - "

logger.debug(SCRIPT_NAME + "Running...")

return next.handle(context, request).thenOnResult {
    response -> {
        if(response.status.isClientError()){
            logger.debug("{} Response has status {} - which is a Client Error", SCRIPT_NAME, response.status)
            response.entity.getJsonAsync().then(errorResponse -> {
                logger.debug("{} Response has body {}", SCRIPT_NAME, errorResponse)
                try {
                    if(errorResponse.error_description.equals("code_verifier parameter required")){
                        logger.debug("{} changing error from {} to {}", SCRIPT_NAME, errorResponse.error,
                                "invalid_grant")
                        errorResponse.error = "invalid_grant"
                        response.entity.setJson(errorResponse)
                    } else if (errorResponse.error_description.equals("The redirection URI provided does not match a " +
                            "pre-registered value.")){
                        logger.debug("{} changing error from {} to {}", SCRIPT_NAME, errorResponse.error,
                                "invalid_grant")
                        errorResponse.error = "invalid_request_object"
                        response.entity.setJson(errorResponse)
                    }
                } catch (e){
                    logger.debug("{} error casting json body to be ErrorResponse. Exception: {}" SCRIPT_NAME, e)
                }
            })
        }
    }
};