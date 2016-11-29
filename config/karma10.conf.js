module.exports = function(config) {
    config.set({
        basePath:'../',
        frameworks:['jasmine'],
        files:[
            {pattern:'bower_components/angular/angular.js'},
            {pattern:'bower_components/angular-route/angular-route.js'},
            {pattern:'bower_components/angular-mocks/angular-mocks.js'},
            {pattern:'bower_components/binartajs/src/binarta.js'},
            {pattern:'bower_components/binartajs/src/checkpoint.js'},
            {pattern:'bower_components/binartajs/src/gateways.inmem.js'},
            {pattern:'bower_components/binartajs-angular1/src/binarta-angular.js'},
            {pattern:'bower_components/binartajs-angular1/src/binarta-checkpoint-angular.js'},
            {pattern:'bower_components/binartajs-angular1/src/binarta-checkpoint-inmem-angular.js'},
            {pattern:'bower_components/binarta.usecase.adapter.angular/src/angular.usecase.adapter.js'},
            {pattern:'bower_components/thk-rest-client-mock/src/rest.client.mock.js'},
            {pattern:'bower_components/thk-notifications-mock/src/notifications.mock.js'},
            {pattern:'bower_components/binarta.web.storage.angular/src/web.storage.js'},
            {pattern:'src/**/*.js'},
            {pattern:'test/**/*.js'}
        ],
        browsers:['PhantomJS']
    });
};