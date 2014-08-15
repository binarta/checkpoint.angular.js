angular.module('checkpoint', ['ngRoute', 'config'])
    .service('account', ['$http', 'config', 'topicRegistry', AccountService])
    .factory('fetchAccountMetadata', ['account', FetchAccountMetadata])
    .factory('activeUserHasPermission', ['account', ActiveUserHasPermission])
    .factory('registrationRequestMessageMapper', ['config', 'registrationRequestMessageMapperRegistry', RegistrationRequestMessageMapperFactory])
    .factory('registrationRequestMessageMapperRegistry', [RegistrationRequestMessageMapperRegistry])
    .factory('authRequiredPresenter', ['config', '$location', '$routeParams', AuthRequiredPresenterFactory])
    .directive('checkpointPermission', CheckpointHasDirectiveFactory)
    .directive('checkpointPermissionFor', CheckpointPermissionForDirectiveFactory)
    .directive('checkpointIsAuthenticated', ['ngRegisterTopicHandler', 'fetchAccountMetadata', CheckpointIsAuthenticatedDirectiveFactory])
    .directive('isAuthenticated', IsAuthenticatedDirectiveFactory)
    .directive('isUnauthenticated', IsUnauthenticatedDirectiveFactory)
    .directive('authenticatedWithRealm', AuthenticatedWithRealmDirectiveFactory)
    .controller('SigninController', ['$scope', 'usecaseAdapterFactory', 'restServiceHandler', '$http', '$location', 'config', 'topicMessageDispatcher', SigninController])
    .controller('AccountMetadataController', ['$scope', 'topicRegistry', 'fetchAccountMetadata', 'authRequiredPresenter', AccountMetadataController])
    .controller('RegistrationController', ['$scope', 'usecaseAdapterFactory', 'config', 'restServiceHandler', '$location', RegistrationController])
    .config(['$routeProvider', function ($routeProvider) {
        $routeProvider
            .when('/signin', {templateUrl: 'partials/checkpoint/signin.html', controller: SigninController})
            .when('/:locale/signin', {templateUrl: 'partials/checkpoint/signin.html', controller: SigninController})
    }]);

function SignoutController($scope, $http, topicMessageDispatcher, config) {
    $scope.submit = function () {
        var onSuccess = function () {
            topicMessageDispatcher.fire('checkpoint.signout', 'ok');
        };

        $http.delete((config.baseUri || '') + 'api/checkpoint', {withCredentials: true}).success(onSuccess);
    }
}
SignoutController.$inject = ['$scope', '$http', 'topicMessageDispatcher', 'config'];

function SigninController($scope, usecaseAdapterFactory, restServiceHandler, $http, $location, config, topicMessageDispatcher) {
    var self = this;
    self.config = {};

    $scope.init = function (config) {
        self.config = config;
    };

    function isRedirectEnabled() {
        return !self.config.noredirect;
    }

    $scope.submit = function (args) {
        var onSuccessCallback = function () {
            topicMessageDispatcher.fire('checkpoint.signin', 'ok');
            if(isRedirectEnabled()) $location.path(config.onSigninSuccessTarget || config.redirectUri || '/');
            config.onSigninSuccessTarget = undefined;
            if(args && args.success) args.success();
        };

        var ctx = usecaseAdapterFactory($scope, onSuccessCallback, {
            rejected:function() {
                self.rejected = true
            }
        });
        var baseUri = config.baseUri || '';
        ctx.params = {
            url: baseUri + 'api/checkpoint',
            method: 'POST',
            data: {
                username: $scope.username,
                password: $scope.password,
                rememberMe: $scope.rememberMe,
                namespace: config.namespace
            },
            withCredentials:true
        };

        self.rejected = false;
        restServiceHandler(ctx);
    };

    $scope.rejected = function () {
        return self.rejected;
    };
}

function AccountService($http, config, topicRegistry) {
    var metadataPromise, permissionPromise;

    ['checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
        topicRegistry.subscribe(topic, function () {
            metadataPromise = undefined;
            permissionPromise = undefined;
        });
    });

    function getMetadata() {
        if(angular.isUndefined(metadataPromise)) {
            metadataPromise = $http.get(config.baseUri + 'api/account/metadata', {
                withCredentials: true,
                headers: {
                    'X-Namespace': config.namespace
                }
            }).then(function (metadata) {
                return metadata.data;
            });
        }
        return metadataPromise;
    }

    function getPermissions() {
        if(angular.isUndefined(permissionPromise)) {
            permissionPromise = getMetadata().then(function (metadata) {
                return $http.post(config.baseUri + 'api/query/permission/list', {
                        filter: {
                            namespace: config.namespace,
                            owner: metadata.principal
                        }
                    },{withCredentials: true})
                    .then(function (permissions) {
                        return permissions.data;
                    });
            });
        }
        return permissionPromise;
    }

    return {
        getMetadata: getMetadata,
        getPermissions: getPermissions
    };
}

function FetchAccountMetadata(account) {
    return function (it) {
        account.getMetadata().then(function(metadata) {
            it.ok(metadata);
        }, function() {
            it.unauthorized();
        });
    };
}

function AccountMetadataController($scope, topicRegistry, fetchAccountMetadata, authRequiredPresenter) {
    var self = this;

    var init = function () {
        fetchAccountMetadata({
            unauthorized: function () {
                self.status = 'unauthorized';
            },
            ok: function (it) {
                self.status = 'ok';
                $scope.metadata = it;
            }
        });
    };

    $scope.unauthorized = function () {
        return self.status == 'unauthorized';
    };

    $scope.authorized = function () {
        return self.status == 'ok';
    };

    [
        {topic: 'app.start', command: init},
        {topic: 'checkpoint.signin', command: init},
        {topic: 'checkpoint.signout', command: init},
        {topic: 'checkpoint.auth.required', command: function(target) {
            authRequiredPresenter(target, $scope);
        }}
    ].forEach(function (it) {
            topicRegistry.subscribe(it.topic, it.command);
        });
}

function ActiveUserHasPermission(account) {
    return function (response, permission) {
        account.getPermissions().then(function(permissions) {
            permissions.reduce(function (result, it) {
                return result || it.name == permission
            }, false) ? response.yes() : response.no();
        }, function() {
            response.no();
        });
    };
}

// @deprecated Try to use the less intrusive checkpointPermissionFor directive
function CheckpointHasDirectiveFactory(ngRegisterTopicHandler, activeUserHasPermission) {
    return {
        restrict: 'A',
        transclude: true,
        template: '<span ng-if="permitted" ng-transclude></span>',
        link: function (scope, el, attrs) {
            var init = function () {
                activeUserHasPermission({
                    no: function () {
                        scope.permitted = false;
                    },
                    yes: function () {
                        scope.permitted = true;
                    }
                }, attrs.for);
            };
            init();

            ['checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
                ngRegisterTopicHandler(scope, topic, function (msg) {
                    init();
                });
            });
        }
    };
}

function CheckpointPermissionForDirectiveFactory(ngRegisterTopicHandler, activeUserHasPermission) {
    return {
        scope: true,
        link: function (scope, el, attrs) {
            var init = function () {
                activeUserHasPermission({
                    no: function () {
                        scope.permitted = false;
                    },
                    yes: function () {
                        scope.permitted = true;
                    }
                }, attrs.checkpointPermissionFor);
            };
            init();

            ['checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
                ngRegisterTopicHandler(scope, topic, function (msg) {
                    init();
                });
            });
        }
    };
}

function CheckpointIsAuthenticatedDirectiveFactory(ngRegisterTopicHandler, fetchAccountMetadata) {
    return {
        scope: true,
        link: function (scope) {
            var init = function () {
                fetchAccountMetadata({
                    ok: function () {
                        scope.authenticated = true
                    },
                    unauthorized: function () {
                        scope.authenticated = false
                    }
                })
            };
            init();

            ['checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
                ngRegisterTopicHandler(scope, topic, function () {
                    init();
                });
            });
        }
    };
}

// @deprecated use CheckpointIsAuthenticated directive instead
function IsAuthenticatedDirectiveFactory(fetchAccountMetadata) {
    return {
        restrict: 'E',
        scope: {},
        transclude: true,
        template: '<div ng-show="authenticated"><span ng-transclude></span></div>',
        link: function (scope) {
            fetchAccountMetadata({
                ok: function () {
                    scope.authenticated = true
                },
                unauthorized: function () {
                    scope.authenticated = false
                }
            })
        }
    }
}

// @deprecated use CheckpointIsAuthenticated directive instead
function IsUnauthenticatedDirectiveFactory(fetchAccountMetadata) {
    return {
        restrict: 'E',
        scope: {},
        transclude: true,
        template: '<div ng-show="unauthenticated"><span ng-transclude></span></div>',
        link: function (scope) {
            fetchAccountMetadata({
                ok: function () {
                    scope.unauthenticated = false
                },
                unauthorized: function () {
                    scope.unauthenticated = true
                }
            })
        }
    }
}

function AuthenticatedWithRealmDirectiveFactory(fetchAccountMetadata, topicRegistry) {
    return {
        restrict: 'E',
        scope: {},
        transclude: true,
        template: '<div ng-show="realm"><span ng-transclude></span></div>',
        link: function(scope, el, attrs) {
            var init = function() {
                fetchAccountMetadata({
                    ok: function(payload) {
                        scope.realm = payload.realm == attrs.realm;
                    },
                    unauthorized: function() {
                        scope.realm = false;
                    }
                })
            };

            ['checkpoint.signin', 'checkpoint.signout', 'app.start'].forEach(function (topic) {
                topicRegistry.subscribe(topic, function (msg) {
                    init();
                });
            });
        }
    }
}

function RegistrationRequestMessageMapperRegistry() {
    var mappers = [];
    return {
        add:function(mapper) {
            mappers.push(mapper);
        },
        all:function() {
            return mappers;
        }
    }
}

function RegistrationRequestMessageMapperFactory(config, registrationRequestMessageMapperRegistry) {
    return function(scope) {
        return registrationRequestMessageMapperRegistry.all().reduce(function(p, c) {
            return c(scope)(p);
        }, {
            namespace: config.namespace,
            username: scope.username,
            email: scope.email,
            alias: scope.username,
            password: scope.password,
            vat: scope.vat
        })
    }
}

function RegistrationController($scope, usecaseAdapterFactory, config, restServiceHandler, $location, topicMessageDispatcher, registrationRequestMessageMapper) {
    $scope.register = function() {
        var onSuccess = function() {
            topicMessageDispatcher.fire('system.success', {
                code:'checkpoint.registration.completed',
                default:'Congratulations, your account has been created.'
            });
            $location.path(($scope.locale ? $scope.locale : '') + '/signin')
        };
        var presenter = usecaseAdapterFactory($scope, onSuccess, {
            rejected:function() {
                topicMessageDispatcher.fire('checkpoint.registration.rejected', 'rejected');
            }
        });
        var baseUri = config.baseUri || '';
        presenter.params = {
            url: baseUri + 'api/accounts',
            method: 'PUT',
            data: registrationRequestMessageMapper($scope)
        };
        restServiceHandler(presenter);
    }
}

function AuthRequiredPresenterFactory(config, $location, $routeParams) {
    return function(target) {
        config.onSigninSuccessTarget = target;
        $location.path($routeParams.locale ? '/' + $routeParams.locale + '/signin' : '/signin');
    }
}
