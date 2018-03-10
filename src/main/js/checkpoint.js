angular.module('checkpoint', ['ngRoute', 'config', 'notifications', 'angular.usecase.adapter', 'rest.client', 'binarta-checkpointjs-angular1'])
    .service('account', ['binarta', '$log', '$http', '$q', 'config', 'topicRegistry', 'authRequiredPresenter', AccountService])
    .factory('fetchAccountMetadata', ['account', 'ngRegisterTopicHandler', '$log', FetchAccountMetadata])
    .factory('activeUserHasPermission', ['account', 'ngRegisterTopicHandler', '$log', ActiveUserHasPermission])
    .factory('registrationRequestMessageMapper', ['config', 'registrationRequestMessageMapperRegistry', RegistrationRequestMessageMapperFactory])
    .factory('registrationRequestMessageMapperRegistry', [RegistrationRequestMessageMapperRegistry])
    .factory('authRequiredPresenter', ['config', '$location', '$routeParams', AuthRequiredPresenterFactory])
    .factory('signinService', ['binarta', 'topicMessageDispatcher', '$log', SigninServiceFactory])
    .factory('signInWithTokenService', ['signinService', '$location', SignInWithTokenServiceFactory])
    .directive('checkpointPermission', ['ngRegisterTopicHandler', 'activeUserHasPermission', '$log', CheckpointHasDirectiveFactory])
    .directive('checkpointPermissionFor', ['binarta', CheckpointPermissionForDirectiveFactory])
    .directive('checkpointIsAuthenticated', ['binarta', CheckpointIsAuthenticatedDirectiveFactory])
    .directive('isAuthenticated', ['fetchAccountMetadata', '$log', IsAuthenticatedDirectiveFactory])
    .directive('isUnauthenticated', ['fetchAccountMetadata', '$log', IsUnauthenticatedDirectiveFactory])
    .directive('authenticatedWithRealm', ['fetchAccountMetadata', 'topicRegistry', AuthenticatedWithRealmDirectiveFactory])
    .controller('SigninController', ['$scope', '$location', 'config', 'signinService', 'account', 'binarta', SigninController])
    .controller('AccountMetadataController', ['$scope', 'binarta', AccountMetadataController])
    .controller('RegistrationController', ['$scope', 'config', '$location', 'topicMessageDispatcher', 'binarta', RegistrationController])
    .controller('SignoutController', ['$scope', '$log', 'binarta', 'topicMessageDispatcher', SignoutController])
    .controller('welcomeMessageController', ['$location', '$rootScope', WelcomeMessageController])
    .config(['$routeProvider', function ($routeProvider) {
        $routeProvider
            .when('/signin', {
                templateUrl: 'partials/checkpoint/signin.html',
                controller: 'SigninController as checkpoint'
            })
            .when('/:locale/signin', {
                templateUrl: 'partials/checkpoint/signin.html',
                controller: 'SigninController as checkpoint'
            })
            .when('/register', {
                templateUrl: 'partials/register.html',
                controller: 'RegistrationController as checkpoint'
            })
            .when('/:locale/register', {
                templateUrl: 'partials/register.html',
                controller: 'RegistrationController as checkpoint'
            })
    }])
    .run(['binartaIsInitialised', 'account', InitCaches]);

function InitCaches(binartaIsInitialised, account) {
    binartaIsInitialised.then(function () {
        account.refreshCaches();
    });
}

function SignoutController($scope, $log, binarta, topicMessageDispatcher) {
    $scope.submit = function () {
        $log.warn('@deprecated SignoutController.submit() - use binarta.checkpoint.profile.signout() instead!');
        binarta.checkpoint.profile.signout({
            unauthenticated: function () {
                topicMessageDispatcher.fire('checkpoint.signout', 'ok');
            }
        });
    }
}

function SigninServiceFactory(binarta, topicMessageDispatcher, $log) {
    return function (args) {
        $log.warn('@deprecated SigninService.execute() - use binarta.checkpoint.signinForm.submit() instead!');
        var onSuccessCallback = function () {
            topicMessageDispatcher.fire('checkpoint.signin', 'ok');
            args.success();
        };

        var data = {};
        Object.keys(args.request).forEach(function (k) {
            data[k] = args.request[k];
        });

        binarta.checkpoint.signinForm.submit(data, {
            success: onSuccessCallback,
            rejected: function (report) {
                if (args.rejected) args.rejected(report);
            }
        });
    }
}

function SigninController($scope, $location, config, signinService, account, binarta) {
    var self = this;

    if(binarta.checkpoint.profile.isAuthenticated())
        $location.path('/');
    else {
        self.config = {};

        $scope.username = $location.search().username;
        self.username = $scope.username;

        $scope.init = init;
        self.init = init;
        function init(config) {
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
                $scope: $scope,
                request: {
                    username: scope.username,
                    password: scope.password,
                    rememberMe: scope.rememberMe
                },
                success: function () {
                    if (isRedirectEnabled()) $location.path(config.onSigninSuccessTarget || config.redirectUri || '/');
                    config.onSigninSuccessTarget = undefined;
                    if (args && args.success) args.success();
                },
                rejected: function () {
                    self.rejected = true;
                    scope.violation = 'credentials.mismatch';
                }
            });
        }

        $scope.rejected = function () {
            return binarta.checkpoint.signinForm.violation();
        };
    }
}

function AccountService(binarta, $log, $http, $q, config, topicRegistry, authRequiredPresenter) {
    var isProfileRefreshed = $q.defer();
    isProfileRefreshed.resolve(); // assume the profile has already been refreshed.

    var metadataPromise, permissionPromise;
    var self = this;

    binarta.checkpoint.signinForm.eventRegistry.add(new UserSessionListener(self));

    this.refreshCaches = function () {
        metadataPromise = undefined;
        permissionPromise = undefined;
        isProfileRefreshed = $q.defer();
        binarta.checkpoint.profile.refresh({
            success: isProfileRefreshed.resolve,
            unauthenticated: isProfileRefreshed.reject
        });
    };

    ['checkpoint.signout'].forEach(function (topic) {
        topicRegistry.subscribe(topic, self.refreshCaches);
    });

    topicRegistry.subscribe('checkpoint.auth.required', function (target) {
        self.refreshCaches();
        authRequiredPresenter(target);
    });

    this.getMetadata = function () {
        $log.warn('@deprecated AccountService.getMetadata() - use binarta.checkpoint.profile.metadata() instead!');
        if (angular.isUndefined(metadataPromise)) {
            var d = $q.defer();
            metadataPromise = d.promise;
            isProfileRefreshed.promise.then(function () {
                if (binarta.checkpoint.profile.isAuthenticated())
                    d.resolve(binarta.checkpoint.profile.metadata());
                else
                    d.reject();
            }, d.reject);
        }
        return metadataPromise;
    };

    this.getPermissions = function () {
        $log.warn('@deprecated AccountService.getPermissions() - use binarta.checkpoint.profile.permissions() instead!');
        if (angular.isUndefined(permissionPromise)) {
            var d = $q.defer();
            permissionPromise = d.promise;
            isProfileRefreshed.promise.then(function () {
                d.resolve(binarta.checkpoint.profile.permissions());
            });
        }
        return permissionPromise;
    };

    this.hasPermission = function (permission) {
        var deferred = $q.defer();
        self.getPermissions().then(function (permissions) {
            permissions.reduce(function (result, it) {
                return result || it.name == permission
            }, false) ? deferred.resolve(true) : deferred.resolve(false);
        }, function () {
            deferred.resolve(false);
        });
        return deferred.promise;
    };

    function UserSessionListener(self) {
        this.signedin = function () {
            self.refreshCaches();
        };
    }
}

function FetchAccountMetadata(account, ngRegisterTopicHandler, $log) {
    return function (response) {
        $log.warn('@deprecated FetchAccountMetadata - use binarta.checkpoint.profile.metadata() instead!');
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

function AccountMetadataController($scope, binarta) {
    var self = this;

    var observer = binarta.checkpoint.profile.eventRegistry.observe({
        signedin: onSignedIn,
        signedout: onSignedOut
    });

    binarta.checkpoint.profile.isAuthenticated() ? onSignedIn() : onSignedOut();

    function onSignedIn() {
        self.status = 'ok';
        $scope.metadata = binarta.checkpoint.profile.metadata();
    }

    function onSignedOut() {
        self.status = 'unauthorized';
        $scope.metadata = undefined;
    }

    $scope.unauthorized = function () {
        return self.status == 'unauthorized';
    };

    $scope.authorized = function () {
        return self.status == 'ok';
    };

    $scope.$on('$destroy', function () {
        observer.disconnect();
    });
}

function ActiveUserHasPermission(account, ngRegisterTopicHandler, $log) {
    return function (response, permission) {
        $log.warn('@deprecated ActiveUserHasPermission - use binarta.checkpoint.profile.hasPermission() instead!');
        function no() {
            if (response.no) response.no();
        }

        function yes() {
            if (response.yes) response.yes();
        }

        function checkPermission() {
            account.getPermissions().then(function (permissions) {
                permissions.reduce(function (result, it) {
                    return result || it.name == permission
                }, false) ? yes() : no();
            }, function () {
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

function CheckpointHasDirectiveFactory(ngRegisterTopicHandler, activeUserHasPermission, $log) {
    return {
        restrict: 'A',
        transclude: true,
        template: '<span ng-if="permitted" ng-transclude></span>',
        link: function (scope, el, attrs) {
            $log.warn('@deprecated checkpoint-permission directive - use checkpoint-permission-for instead!');
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

function CheckpointPermissionForDirectiveFactory(binarta) {
    return {
        scope: true,
        link: function (scope, el, attrs) {
            function refresh() {
                scope.permitted = binarta.checkpoint.profile.hasPermission(attrs.checkpointPermissionFor);
            }

            var listener = {
                signedin: refresh,
                signedout: function () {
                    scope.permitted = false;
                }
            };
            binarta.checkpoint.profile.eventRegistry.add(listener);
            refresh();
            scope.$on('$destroy', function () {
                binarta.checkpoint.profile.eventRegistry.remove(listener);
            });
        }
    };
}

function CheckpointIsAuthenticatedDirectiveFactory(binarta) {
    return {
        scope: true,
        link: function (scope) {
            var observer = binarta.checkpoint.profile.eventRegistry.observe({
                signedin: onSignedIn,
                signedout: onSignedOut
            });

            binarta.checkpoint.profile.isAuthenticated() ? onSignedIn() : onSignedOut();

            function onSignedIn() {
                scope.authenticated = true;
            }

            function onSignedOut() {
                scope.authenticated = false;
            }

            scope.$on('$destroy', observer.disconnect);
        }
    };
}

function IsAuthenticatedDirectiveFactory(fetchAccountMetadata, $log) {
    return {
        restrict: 'E',
        scope: {},
        transclude: true,
        template: '<div ng-show="authenticated"><span ng-transclude></span></div>',
        link: function (scope) {
            $log.warn('@deprecated is-authenticated directive - use checkpoint-is-authenticated instead!');
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

function IsUnauthenticatedDirectiveFactory(fetchAccountMetadata, $log) {
    return {
        restrict: 'E',
        scope: {},
        transclude: true,
        template: '<div ng-show="unauthenticated"><span ng-transclude></span></div>',
        link: function (scope) {
            $log.warn('@deprecated is-unauthenticated directive - use checkpoint-is-authenticated instead!');
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
        link: function (scope, el, attrs) {
            var init = function () {
                fetchAccountMetadata({
                    ok: function (payload) {
                        scope.realm = payload.realm == attrs.realm;
                    },
                    unauthorized: function () {
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
        add: function (mapper) {
            mappers.push(mapper);
        },
        all: function () {
            return mappers;
        }
    }
}

function RegistrationRequestMessageMapperFactory(config, registrationRequestMessageMapperRegistry) {
    return function (scope) {
        return registrationRequestMessageMapperRegistry.all().reduce(function (p, c) {
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

function RegistrationController($scope, config, $location, topicMessageDispatcher, binarta) {
    var self = this;

    $scope.recaptchaPublicKey = config.recaptchaPublicKey;
    self.recaptchaPublicKey = config.recaptchaPublicKey;

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
            var onSuccess = function () {
                topicMessageDispatcher.fire('system.success', {
                    code: 'checkpoint.registration.completed',
                    default: 'Congratulations, your account has been created.'
                });

                $location.path(config.onSigninSuccessTarget || '/');
                config.onSigninSuccessTarget = undefined;
            };
            binarta.checkpoint.registrationForm.submit(scope, {
                success: onSuccess,
                rejected: function () {
                    topicMessageDispatcher.fire('checkpoint.registration.rejected', 'rejected');
                }
            });
        }
    }
}

function AuthRequiredPresenterFactory(config, $location, $routeParams) {
    return function (target) {
        var pathToSignin = $routeParams.locale ? '/' + $routeParams.locale + '/signin' : '/signin';
        if (target != pathToSignin) {
            config.onSigninSuccessTarget = target;
            $location.path(pathToSignin);
        }
    }
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
    return function (args) {
        var token = args && args.token || $location.search().autoSigninToken;
        if (token) signinService({
            $scope: {},
            request: {
                token: token
            },
            success: function () {
                $location.search('autoSigninToken', undefined).replace();
            }
        })
    }
}