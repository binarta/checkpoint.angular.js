angular.module("checkpoint.accounts", ['ngRoute'])
    .controller('RecoverPasswordController', ['$scope', 'usecaseAdapterFactory', 'config', 'restServiceHandler', 'recoverPasswordPresenter', RecoverPasswordController])
    .controller('ResetPasswordController', ['$scope', 'usecaseAdapterFactory', 'config', 'restServiceHandler', '$location', 'resetPasswordPresenter', ResetPasswordController])
    .controller('ChangeMyPasswordController', ['$scope', '$http', 'config', ChangeMyPasswordController])
    .factory('resetPasswordPresenter', ['$location', 'topicMessageDispatcher', ResetPasswordPresenterFactory])
    .factory('recoverPasswordPresenter', ['$location', RecoverPasswordPresenterFactory])
    .config(['$routeProvider', function($routeProvider) {
        $routeProvider
            .when('/changemypassword', {templateUrl:'partials/checkpoint/changemypassword.html', controller: 'ChangeMyPasswordController as checkpoint'})
            .when('/password/reset', {templateUrl:'partials/checkpoint/reset-password.html', controller: 'ResetPasswordController as checkpoint'})
            .when('/password/recover', {templateUrl:'partials/checkpoint/recover-password.html', controller: 'RecoverPasswordController as checkpoint'})
            .when('/password/token/sent', {templateUrl:'partials/checkpoint/password-token-sent.html'})
            .when('/:locale/changemypassword', {templateUrl:'partials/checkpoint/changemypassword.html', controller: 'ChangeMyPasswordController as checkpoint'})
            .when('/:locale/password/reset', {templateUrl:'partials/checkpoint/reset-password.html', controller: 'ResetPasswordController as checkpoint'})
            .when('/:locale/password/recover', {templateUrl:'partials/checkpoint/recover-password.html', controller: 'RecoverPasswordController as checkpoint'})
            .when('/:locale/password/token/sent', {templateUrl:'partials/checkpoint/password-token-sent.html'})
    }]);

function ChangeMyPasswordController($scope, $http, config) {
    var self = this;

    var onSuccess = function () {
        $scope.ok = true;
        self.ok = true;
        resetFields();
    };

    var onError = function (body, status) {
        var handlers = {
            403: function () {
                $scope.forbidden = true;
                self.forbidden = true;
            }
        };
        if (handlers[status] == undefined) alert(status + ' - ' + body);
        else handlers[status]();
    };

    var resetStates = function () {
        $scope.ok = false;
        $scope.forbidden = false;
        self.ok = false;
        self.forbidden = false;
    };

    var resetFields = function () {
        $scope.currentPassword = '';
        $scope.newPassword = '';
        self.currentPassword = '';
        self.newPassword = '';
    };
    resetFields();

    $scope.submit = function () {
        submit($scope);
    };
    self.submit = function () {
        submit(self);
    };
    function submit (ctx) {
        resetStates();
        $http.post((config.baseUri || '') + 'api/account/password', {
            currentPassword: ctx.currentPassword,
            newPassword: ctx.newPassword
        }, {withCredentials:true}).success(onSuccess).error(onError);
    }

    resetStates();
}

function RecoverPasswordController($scope, usecaseAdapterFactory, config, restServiceHandler, recoverPasswordPresenter) {
    var self = this;

    function toBaseUri() {
        return config.baseUri || '';
    }

    $scope.submit = function () {
        submit($scope);
    };
    self.submit = function () {
        submit(self);
    };

    function submit (ctx) {
        ctx.violation = '';
        var presenter = usecaseAdapterFactory($scope, function () {
                recoverPasswordPresenter($scope);
            }, {
                rejected: function (violations) {
                    if (violations.email.indexOf('required') != -1) ctx.violation = 'email.required';
                    else if (violations.email.indexOf('email') != -1) ctx.violation = 'email.invalid';
                    else if (violations.email.indexOf('mismatch') != -1) ctx.violation = 'email.mismatch';
                }
            }
        );
        presenter.params = {
            method: 'PUT',
            url: toBaseUri() + 'api/entity/password-reset-token',
            data: {
                namespace: config.namespace,
                email: ctx.email || ''
            }
        };
        restServiceHandler(presenter);
    }
}

function ResetPasswordController($scope, usecaseAdapterFactory, config, restServiceHandler, $location, resetPasswordPresenter) {
    var self = this;

    function toBaseUri() {
        return config.baseUri || '';
    }

    if($location.search().username) {
        $scope.username = $location.search().username;
        self.username = $scope.username;
    }

    $scope.submit = function () {
        submit($scope);
    };
    self.submit = function () {
        submit(self);
    };

    function submit (ctx) {
        ctx.violation = '';
        var presenter = usecaseAdapterFactory($scope, function () {
                resetPasswordPresenter($scope);
            }, {
                rejected: function (violations) {
                    if (violations.password) ctx.violation = 'password.required';
                    else if (violations.token) {
                        if (violations.token.indexOf('required') != -1) ctx.violation = 'token.required';
                        else if (violations.token.indexOf('mismatch') != -1) ctx.violation = 'token.mismatch';
                    }
                }
            }
        );
        presenter.params = {
            method: 'POST',
            url: toBaseUri() + 'api/account/reset/password',
            data: {
                namespace: config.namespace,
                password: ctx.password,
                token: $location.search().token
            }
        };
        restServiceHandler(presenter);
    }
}

function ResetPasswordPresenterFactory($location, topicMessageDispatcher) {
    return function(scope) {
        topicMessageDispatcher.fire('system.success', {
            code: 'checkpoint.reset.password.success',
            default: 'Password was successfully updated'
        });
        $location.path(toLocale(scope) + '/signin');
        $location.search('token', null);
    }
}

function toLocale(scope) {
    return scope.locale ? ((scope.locale == 'default') ? '' : '/' + scope.locale) : '';
}

function RecoverPasswordPresenterFactory($location) {
    return function(scope) {
        $location.path(toLocale(scope) + '/password/token/sent')
    };
}