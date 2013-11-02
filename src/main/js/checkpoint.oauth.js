angular.module('checkpoint.oauth', ['config', 'rest.client', 'angular.usecase.adapter', 'notifications'])
    .controller('OauthController' ['$scope', 'restServiceHandler', 'usecaseAdapterFactory', 'config', OauthController])
    .controller('CallbackController', ['$scope', 'config', 'restServiceHandler', 'usecaseAdapterFactory', '$location', 'topicRegistry', CallbackController]);

function OauthController($scope, restServiceHandler, usecaseAdapterFactory, config) {
    $scope.auth = function () {
        var onSuccess = function (payload) {
            window.location = payload.url;
        };
        var baseUri = config.baseUri || '';
        var presenter = usecaseAdapterFactory($scope, onSuccess);
        presenter.params = {
            method: 'GET',
            url: baseUri + 'api/oauth/authenticate/facebook',
            headers: {'X-Namespace': config.namespace}
        };
        restServiceHandler(presenter);
    }
}

function CallbackController($scope, config, restServiceHandler, usecaseAdapterFactory, $location, topicRegistry) {
    $scope.temp = function() {
        topicRegistry.subscribe('app.start', function() {
            var onSuccess = function () {
                window.location = '';
            };
            var baseUri = config.baseUri || '';
            var presenter = usecaseAdapterFactory($scope, onSuccess);
            presenter.params = {
                method: 'PUT',
                url: baseUri + 'api/oauth/callback/facebook',
                data: {code: $location.search()['code']},
                headers: {'X-Namespace': config.namespace },
                withCredentials: true
            };
            restServiceHandler(presenter);
        })
    };
}