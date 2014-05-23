angular.module('checkpoint', ['ngRoute', 'config'])
    .factory('fetchAccountMetadata', ['$http', 'config', 'topicRegistry', FetchAccountMetadata])
    .factory('activeUserHasPermission', ['fetchAccountMetadata', 'topicRegistry', '$http', 'config', ActiveUserHasPermission])
    .factory('registrationRequestMessageMapper', ['config', 'registrationRequestMessageMapperRegistry', RegistrationRequestMessageMapperFactory])
    .factory('registrationRequestMessageMapperRegistry', [RegistrationRequestMessageMapperRegistry])
    .factory('authRequiredPresenter', ['config', '$location', '$routeParams', AuthRequiredPresenterFactory])
    .directive('checkpointPermission', CheckpointHasDirectiveFactory)
    .directive('checkpointPermissionFor', CheckpointPermissionForDirectiveFactory)
    .directive('isAuthenticated', IsAuthenticatedDirectiveFactory)
    .directive('isUnauthenticated', IsUnauthenticatedDirectiveFactory)
    .directive('authenticatedWithRealm', AuthenticatedWithRealmDirectiveFactory)
    .controller('SigninController', ['$scope', '$http', '$location', 'config', 'topicMessageDispatcher', SigninController])
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

function SigninController($scope, $http, $location, config, topicMessageDispatcher) {
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

        var onErrorCallback = function (payload, status) {
            var toViolations = function (payload) {
                return Object.keys(payload).map(function (it) {
                    return {context: it, cause: payload[it][0]}
                });
            };

            self.status = status;
            self.payload = payload;
            if (status == 412) $scope.violations = toViolations(payload);
        };

        $http.post((config.baseUri || '') + 'api/checkpoint', {
            username: $scope.username,
            password: $scope.password,
            rememberMe: $scope.rememberMe,
            namespace: config.namespace
        }, {
            withCredentials: true
        }).success(onSuccessCallback).error(onErrorCallback);
    };

    $scope.rejected = function () {
        return self.status == 412;
    };
}

function FetchAccountMetadata($http, config, topicRegistry) {
    var cache, cached;

    var clearCache = function () {
        cache = {};
        cached = false;
    };
    clearCache();

    topicRegistry.subscribe('checkpoint.signin', clearCache);
    topicRegistry.subscribe('checkpoint.signout', clearCache);

    var usecase = function (it) {
        var onSuccess = function (payload) {
            cached = true;
            cache.payload = payload;
            it.ok(payload);
        };
        var onError = function (payload, status) {
            cached = true;
            cache.payload = payload;
            cache.status = status;
            it.unauthorized();
        };

        if (!cached) {
            var path = config.baseUri || '';
            $http.get(path + 'api/account/metadata', {
                withCredentials: true,
                headers: {
                    'X-Namespace': config.namespace
                }
            }).success(onSuccess).error(onError);
        } else {
            !cache.status ? onSuccess(cache.payload) : onError(cache.payload, cache.status);
        }
    };

    return  usecase
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

function ActiveUserHasPermission(fetchAccountMetadata, topicRegistry, $http, config) {
    var cache, cached;
    var baseUri = '';

    var clearCache = function () {
        cache = [];
        cached = false;
    };
    clearCache();

    topicRegistry.subscribe('checkpoint.signin', clearCache);

    topicRegistry.subscribe('config.initialized', function (config) {
        baseUri = config.baseUri || '';
    });

    return function (response, permission) {
        fetchAccountMetadata({
            unauthorized: function () {
                response.no();
            },
            ok: function (metadata) {
                var onSuccess = function (permissions) {
                    cache = permissions;
                    cached = true;
                    permissions.reduce(function (result, it) {
                        return result || it.name == permission
                    }, false) ? response.yes() : response.no();
                };

                if (!cached) {
                    $http.post(baseUri + 'api/query/permission/list', {filter: {namespace: config.namespace, owner: metadata.principal}}, {
                        withCredentials: true
                    }).success(onSuccess);
                } else
                    onSuccess(cache);
            }
        });
    }
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
    return function (scope, el, attrs) {
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
}

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
