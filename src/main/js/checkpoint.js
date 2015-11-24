angular.module('checkpoint', ['ngRoute', 'config', 'notifications', 'angular.usecase.adapter', 'rest.client', 'ui.bootstrap.modal'])
    .service('account', ['$http', '$q', 'config', 'topicRegistry', 'authRequiredPresenter', AccountService])
    .factory('fetchAccountMetadata', ['account', 'ngRegisterTopicHandler', FetchAccountMetadata])
    .factory('activeUserHasPermission', ['account', 'ngRegisterTopicHandler', ActiveUserHasPermission])
    .factory('registrationRequestMessageMapper', ['config', 'registrationRequestMessageMapperRegistry', RegistrationRequestMessageMapperFactory])
    .factory('registrationRequestMessageMapperRegistry', [RegistrationRequestMessageMapperRegistry])
    .factory('authRequiredPresenter', ['config', '$location', '$routeParams', AuthRequiredPresenterFactory])
    .factory('signinService', ['config', 'usecaseAdapterFactory', 'topicMessageDispatcher', 'restServiceHandler', SigninServiceFactory])
    .factory('signInWithTokenService', ['signinService', '$location', SignInWithTokenServiceFactory])
    .directive('checkpointPermission', ['ngRegisterTopicHandler', 'activeUserHasPermission', CheckpointHasDirectiveFactory])
    .directive('checkpointPermissionFor', ['activeUserHasPermission', CheckpointPermissionForDirectiveFactory])
    .directive('checkpointIsAuthenticated', ['fetchAccountMetadata', CheckpointIsAuthenticatedDirectiveFactory])
    .directive('isAuthenticated', ['fetchAccountMetadata', IsAuthenticatedDirectiveFactory])
    .directive('isUnauthenticated', ['fetchAccountMetadata', IsUnauthenticatedDirectiveFactory])
    .directive('authenticatedWithRealm', ['fetchAccountMetadata', 'topicRegistry', AuthenticatedWithRealmDirectiveFactory])
    .directive('loginModal', ['config', '$modal', LoginModalDirectiveFactory])
    .controller('SigninController', ['$scope', '$location', 'config', 'signinService', 'account', SigninController])
    .controller('AccountMetadataController', ['$scope', 'fetchAccountMetadata', AccountMetadataController])
    .controller('RegistrationController', ['$scope', 'usecaseAdapterFactory', 'config', 'restServiceHandler', '$location', 'topicMessageDispatcher', 'registrationRequestMessageMapper', 'signinService', RegistrationController])
    .controller('SignoutController', ['$scope', '$http', 'topicMessageDispatcher', 'config', SignoutController])
    .controller('welcomeMessageController', ['$location','$rootScope', WelcomeMessageController])
    .config(['$routeProvider', function ($routeProvider) {
        $routeProvider
            .when('/signin', {templateUrl: 'partials/checkpoint/signin.html', controller: 'SigninController as checkpoint'})
            .when('/:locale/signin', {templateUrl: 'partials/checkpoint/signin.html', controller: 'SigninController as checkpoint'})
            .when('/register', {templateUrl: 'partials/register.html', controller: 'RegistrationController as checkpoint'})
            .when('/:locale/register', {templateUrl: 'partials/register.html', controller: 'RegistrationController as checkpoint'})
    }]);

function SignoutController($scope, $http, topicMessageDispatcher, config) {
    $scope.submit = function () {
        var onSuccess = function () {
            topicMessageDispatcher.fire('checkpoint.signout', 'ok');
        };

        $http.delete((config.baseUri || '') + 'api/checkpoint', {withCredentials: true}).success(onSuccess);
    }
}

function SigninServiceFactory(config, usecaseAdapterFactory, topicMessageDispatcher, restServiceHandler) {
    return function(args) {
        var onSuccessCallback = function () {
            topicMessageDispatcher.fire('checkpoint.signin', 'ok');
            args.success();
        };

        var ctx = usecaseAdapterFactory(args.$scope, onSuccessCallback, {
            rejected:function() {
                if (args.rejected) args.rejected();
                self.rejected = true
            }
        });

        var data = {};
        Object.keys(args.request).forEach(function(k) {
            data[k] = args.request[k];
        });
        data.namespace = config.namespace;

        var baseUri = config.baseUri || '';
        ctx.params = {
            url: baseUri + 'api/checkpoint',
            method: 'POST',
            data: data,
            withCredentials:true
        };

        restServiceHandler(ctx);
    }
}

function SigninController($scope, $location, config, signinService, account) {
    var self = this;

    account.getMetadata().then(function() {
        $location.path('/');
    }, function () {
        self.config = {};

        $scope.username = $location.search().username;
        self.username = $scope.username;

        $scope.init = init;
        self.init = init;
        function init (config) {
            self.config = config;
        }

        function isRedirectEnabled() {
            return !self.config.noredirect;
        }

        $scope.submit = function (args) {
            submit(args, $scope);
        };
        self.submit = function (args) {
            submit(args, self);
        };

        function submit(args, scope) {
            //Fix for browsers that doesn't trigger an event when auto-filling password fields which in turn won't update variables.
            $('form input[type="password"]').trigger('change');

            self.rejected = false;
            scope.violation = '';
            signinService({
                $scope:$scope,
                request:{
                    username: scope.username,
                    password: scope.password,
                    rememberMe: scope.rememberMe
                },
                success:function() {
                    if(isRedirectEnabled()) $location.path(config.onSigninSuccessTarget || config.redirectUri || '/');
                    config.onSigninSuccessTarget = undefined;
                    if(args && args.success) args.success();
                },
                rejected:function() {
                    self.rejected = true;
                    scope.violation = 'credentials.mismatch';
                }
            });
        }

        $scope.rejected = function () {
            return self.rejected;
        };
    });
}

function AccountService($http, $q, config, topicRegistry, authRequiredPresenter) {
    var metadataPromise, permissionPromise;

    function resetPromises() {
        metadataPromise = undefined;
        permissionPromise = undefined;
    }

    ['checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
        topicRegistry.subscribe(topic, resetPromises);
    });

    topicRegistry.subscribe('checkpoint.auth.required', function(target) {
        resetPromises();
        authRequiredPresenter(target);
    });

    function getMetadata() {
        if(angular.isUndefined(metadataPromise)) {
            metadataPromise = $http.get(config.baseUri + 'api/account/metadata', {
                withCredentials: true,
                headers: {
                    'X-Namespace': config.namespace
                }
            }).then(function (metadata) {
                if (!metadata.data.principal) return $q.reject();
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

function FetchAccountMetadata(account, ngRegisterTopicHandler) {
    return function (response) {
        function getMetadata() {
            account.getMetadata().then(authorized, unauthorized);
        }
        getMetadata();

        function authorized(metadata) {
            if (response.ok) response.ok(metadata);
        }

        function unauthorized() {
            if (response.unauthorized) response.unauthorized();
        }

        if (response.scope) {
            ngRegisterTopicHandler(response.scope, 'checkpoint.signout', function () {
                unauthorized();
            });

            ngRegisterTopicHandler(response.scope, 'checkpoint.signin', function () {
                getMetadata();
            });
        }
    };
}

function AccountMetadataController($scope, fetchAccountMetadata) {
    var self = this;

    fetchAccountMetadata({
        unauthorized: function () {
            self.status = 'unauthorized';
        },
        ok: function (it) {
            self.status = 'ok';
            $scope.metadata = it;
        },
        scope: $scope
    });

    $scope.unauthorized = function () {
        return self.status == 'unauthorized';
    };

    $scope.authorized = function () {
        return self.status == 'ok';
    };
}

function ActiveUserHasPermission(account, ngRegisterTopicHandler) {
    return function (response, permission) {
        function no() {
            if (response.no) response.no();
        }

        function yes() {
            if (response.yes) response.yes();
        }

        function checkPermission() {
            account.getPermissions().then(function(permissions) {
                permissions.reduce(function (result, it) {
                    return result || it.name == permission
                }, false) ? yes() : no();
            }, function() {
                no();
            });
        }
        checkPermission();

        if (response.scope) {
            ngRegisterTopicHandler(response.scope, 'checkpoint.signout', function () {
                no();
            });

            ngRegisterTopicHandler(response.scope, 'checkpoint.signin', function () {
                checkPermission();
            });
        }
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

function CheckpointPermissionForDirectiveFactory(activeUserHasPermission) {
    return {
        scope: true,
        link: function (scope, el, attrs) {
            activeUserHasPermission({
                no: function () {
                    scope.permitted = false;
                },
                yes: function () {
                    scope.permitted = true;
                },
                scope: scope
            }, attrs.checkpointPermissionFor);
        }
    };
}

function CheckpointIsAuthenticatedDirectiveFactory(fetchAccountMetadata) {
    return {
        scope: true,
        link: function (scope) {
            fetchAccountMetadata({
                ok: function () {
                    scope.authenticated = true
                },
                unauthorized: function () {
                    scope.authenticated = false
                },
                scope: scope
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
            email: scope.email,
            username: scope.username || scope.email,
            alias: scope.username || scope.email,
            password: scope.password,
            vat: scope.vat
        })
    }
}

function RegistrationController($scope, usecaseAdapterFactory, config, restServiceHandler, $location, topicMessageDispatcher, registrationRequestMessageMapper, signinService) {
    var self = this;

    $scope.register = function () {
        register($scope);
    };
    this.register = function () {
        register(self);
    };

    function register(scope) {
        if ($scope.registrationForm && $scope.registrationForm.$invalid) {
            $scope.violations = {};
            if ($scope.registrationForm.email.$invalid) $scope.violations.email = ['required'];
            if ($scope.registrationForm.password.$invalid) $scope.violations.password = ['required'];
            if ($scope.registrationForm.vat.$invalid) $scope.violations.vat = ['required'];
        }

        if (!$scope.registrationForm || ($scope.registrationForm && $scope.registrationForm.$valid)) {
            var onSuccess = function() {
                topicMessageDispatcher.fire('system.success', {
                    code:'checkpoint.registration.completed',
                    default:'Congratulations, your account has been created.'
                });

                signinService({
                    $scope: $scope,
                    request: {
                        username: scope.email,
                        password: scope.password,
                        rememberMe: false
                    },
                    success: function () {
                        $location.path(config.onSigninSuccessTarget || '/');
                        config.onSigninSuccessTarget = undefined;
                    }
                });
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
                data: registrationRequestMessageMapper(scope)
            };
            restServiceHandler(presenter);
        }
    }
}

function AuthRequiredPresenterFactory(config, $location, $routeParams) {
    return function(target) {
        var pathToSignin = $routeParams.locale ? '/' + $routeParams.locale + '/signin' : '/signin';
        if (target != pathToSignin) {
            config.onSigninSuccessTarget = target;
            $location.path(pathToSignin);
        }
    }
}

function LoginModalDirectiveFactory(config, $modal) {
    return {
        restrict: 'A',
        scope: true,
        link: function (scope) {
            scope.open = function () {
                var componentsDir = config.componentsDir || 'bower_components';
                var styling = config.styling ? config.styling + '/' : '';

                $modal.open({
                    templateUrl: componentsDir + '/binarta.checkpoint.angular/template/' + styling + 'login-modal.html',
                    backdrop: 'static'
                });
            };
        }
    };
}

function WelcomeMessageController($location, $rootScope) {
    this.welcome = $location.search().welcome;
    if (this.welcome) removeParamOnRouteChange();

    function removeParamOnRouteChange() {
        var removeListener = $rootScope.$on('$routeChangeStart', function () {
            removeListener();
            $location.search('welcome', null);
        });
    }
}

function SignInWithTokenServiceFactory(signinService, $location) {
    return function(args) {
        var token = args && args.token || $location.search().autoSigninToken;
        if (token) signinService({
            $scope:{},
            request:{
                token:token
            },
            success:function() {
                $location.search('autoSigninToken', undefined).replace();
            }
        })
    }
}