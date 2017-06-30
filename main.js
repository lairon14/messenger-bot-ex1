/**
 * Created by lacosta on 29/06/2017.
 */

var apiai = require('apiai');

var app = apiai("5b089b85f44544048e5b9bc49b049583");

var request = app.textRequest('cual es el clima de hoy en Caracas', {
    sessionId: '<unique session id>'
});

request.on('response', function(response) {
    console.log(response.result.fulfillment.speech);
});

request.on('error', function(error) {
    console.log(error);
});

request.end();