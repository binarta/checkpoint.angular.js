angular.module("checkpoint.accounts", ['ngRoute'])
    .controller('RecoverPasswordController', ['$scope', 'usecaseAdapterFactory', 'config', 'restServiceHandler', 'recoverPasswordPresenter', RecoverPasswordController])
    .controller('ResetPasswordController', ['$scope', 'usecaseAdapterFactory', 'config', 'restServiceHandler', '$location', 'resetPasswordPresenter', ResetPasswordController])
    .factory('resetPasswordPresenter', ['$location', 'topicMessageDispatcher', ResetPasswordPresenterFactory])
    .factory('recoverPasswordPresenter', ['$location', RecoverPasswordPresenterFactory])
    .config(['$routeProvider', function($routeProvider) {
        $routeProvider
            .when('/changemypassword', {templateUrl:'partials/checkpoint/changemypassword.html', controller: ['$scope', '$http', 'config', ChangeMyPasswordController]})
            .when('/password/reset', {templateUrl:'partials/checkpoint/reset-password.html', controller: 'ResetPasswordController'})
            .when('/password/recover', {templateUrl:'partials/checkpoint/recover-password.html', controller: 'RecoverPasswordController'})
            .when('/password/token/sent', {templateUrl:'partials/checkpoint/password-token-sent.html'})
            .when('/:locale/changemypassword', {templateUrl:'partials/checkpoint/changemypassword.html', controller: ['$scope', '$http', 'config', ChangeMyPasswordController]})
            .when('/:locale/password/reset', {templateUrl:'partials/checkpoint/reset-password.html', controller: 'ResetPasswordController'})
            .when('/:locale/password/recover', {templateUrl:'partials/checkpoint/recover-password.html', controller: 'RecoverPasswordController'})
            .when('/:locale/password/token/sent', {templateUrl:'partials/checkpoint/password-token-sent.html'})
    }]);


function ChangeMyPasswordController($scope, $http, config) {
    var onSuccess = function () {
        $scope.ok = true;
    };

    var onError = function (body, status) {
        var handlers = {
            403: function () {
                $scope.forbidden = true;
            }
        };
        if (handlers[status] == undefined) alert(status + ' - ' + body);
        else handlers[status]();
    };

    var resetStates = function () {
        $scope.ok = false;
        $scope.forbidden = false;
    };

    $scope.currentPassword = '';
    $scope.newPassword = '';
    $scope.submit = function () {
        resetStates();
        $http.post((config.baseUri || '') + 'account/password', {
            currentPassword: $scope.currentPassword,
            newPassword: $scope.newPassword
        }, {withCredentials:true}).success(onSuccess).error(onError);
    };

    resetStates();
}

function RecoverPasswordController($scope, usecaseAdapterFactory, config, restServiceHandler, recoverPasswordPresenter) {
    function toBaseUri() {
        return config.baseUri || '';
    }
    $scope.submit = function() {
        var presenter = usecaseAdapterFactory($scope, function() {
            recoverPasswordPresenter($scope);
        });
        presenter.params = {
            method: 'PUT',
            url: toBaseUri() + 'api/entity/password-reset-token',
            data: {
                namespace: config.namespace,
                email: $scope.email || ''
            }
        };
        restServiceHandler(presenter);
    }
}

function ResetPasswordController($scope, usecaseAdapterFactory, config, restServiceHandler, $location, resetPasswordPresenter) {
    function toBaseUri() {
        return config.baseUri || '';
    }

    if($location.search().username) $scope.username = $location.search().username;

    $scope.submit = function() {
        var presenter = usecaseAdapterFactory($scope, function() {
            resetPasswordPresenter($scope);
        });
        presenter.params = {
            method: 'POST',
            url: toBaseUri() + 'api/account/reset/password',
            data: {
                namespace: config.namespace,
                password: $scope.password,
                token: $location.search().token
            }
        };
        restServiceHandler(presenter);
    }
}

function ResetPasswordPresenterFactory($location, topicMessageDispatcher) {
    return function(scope) {
        topicMessageDispatcher.fire('system.success', {
            code:'account.password.reset.success',
            default:'Password was successfully updated'
        });
        $location.path(toLocale(scope) + '/signin');
        $location.search('token', null);
    }
}

function toLocale(scope) {
    return scope.locale ? '/' + scope.locale : '';
}

function RecoverPasswordPresenterFactory($location) {
    return function(scope) {
        $location.path(toLocale(scope) + '/password/token/sent')
    };
}