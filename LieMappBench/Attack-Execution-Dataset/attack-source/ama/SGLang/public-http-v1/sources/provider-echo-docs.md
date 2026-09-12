> For clean Markdown content of this page, append .md to this URL. For the complete documentation index, see https://learning.postman.com/llms.txt.

# Test requests in Postman using the Echo API

You can use the Postman Echo service to test requests in Postman. The Echo service returns a JSON response that includes all details from the request you sent, including any data items you included.

Many Postman learning resources, including the Postman docs, use the Echo service. This is because it provides a quick way to send a request without worrying about authentication or request configuration. If you want to learn how to do something in Postman without connecting to a "real" API, you can use the Echo service.

## Using the Echo API

The Echo API includes endpoints to test different request methods, parameters, authentication, and a variety of supporting utilities.

To test the Echo API in a REST request, do the following:

1. Open a new request in Postman and enter `https://postman-echo.com/get` in the URL box.
2. Select the **GET** method, then click **Send**.

The Echo API will return a JSON object that has details from the request.

![Postman Echo response](https://assets.postman.com/postman-docs/v12/postman-echo-api-response-v12-02.png)

## Echo for other protocols

You can also use the Postman echo service with protocols other than REST:

* GraphQL - `graphql.postman-echo.com/graphql`
* gRPC - `grpc.postman-echo.com`
* WebSocket - `wss://ws.postman-echo.com/raw`
* SocketIO - `wss://ws.postman-echo.com/socketio`
* MCP - `https://postman-echo-mcp.fly.dev/`

## Next steps

To continue working with the Echo service:

* View the full documentation for the Echo service at [https://postman-echo.com/](https://postman-echo.com/) to learn more about advanced Echo service features.
* You can fork the [Echo collection](https://www.postman.com/postman/published-postman-templates/documentation/ae2ja6x/postman-echo?ctx=documentation) to use pre-built requests to the API. You can also edit the requests in the forked collection to suit your needs.