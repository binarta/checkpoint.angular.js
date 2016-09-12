describe('checkpoint', function () {
    var self = this;
    var $controller, jQuerySelector, jQueryTriggeredEvent;
    var binarta, ctrl, $rootScope, scope, $httpBackend, location, dispatcher, registry, config;
    var payload = {};
    var usecaseAdapter;
    var rest;
    var presenter;

    var username = 'johndoe';
    var password = '1234';
    var rememberMe = true;

    beforeEach(module('binartajs-angular1-spec'));
    beforeEach(module('checkpoint'));
    beforeEach(module('rest.client'));
    beforeEach(module('notifications'));
    beforeEach(module('angular.usecase.adapter'));
    beforeEach(inject(function (_binarta_, binartaCheckpointGateway, _$rootScope_, $injector, $location, topicMessageDispatcherMock, topicRegistryMock, usecaseAdapterFactory, restServiceHandler) {
        binarta = _binarta_;
        $rootScope = _$rootScope_;
        scope = $rootScope.$new();
        config = $injector.get('config');
        location = $location;
        $httpBackend = $injector.get('$httpBackend');
        dispatcher = topicMessageDispatcherMock;
        registry = topicRegistryMock;
        usecaseAdapter = usecaseAdapterFactory;
        rest = restServiceHandler;
        presenter = {};
        usecaseAdapter.and.returnValue(presenter);

        jQuerySelector = undefined;
        jQueryTriggeredEvent = undefined;
        $ = function (selector) {
            jQuerySelector = selector;
            return {
                trigger: function (event) {
                    jQueryTriggeredEvent = event;
                }
            }
        };

        binartaCheckpointGateway.signout();
    }));

    afterEach(function () {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('SignoutController', function () {
        beforeEach(inject(function ($controller) {
            ctrl = $controller(SignoutController, {$scope: scope, config: {}});
        }));

        it('on submit success', function () {
            scope.submit();
            expect(dispatcher['checkpoint.signout']).toEqual('ok');
        });
    });

    describe('SigninService', function () {
        var service;

        beforeEach(inject(function (config, signinService) {
            service = signinService;
            binarta.checkpoint.registrationForm.submit({username: username, password: password});
            binarta.checkpoint.profile.signout();
        }));

        describe('on execute', function () {
            var successCallbackExecuted = false;
            var success = function () {
                successCallbackExecuted = true;
            };

            beforeEach(function () {
                service({
                    $scope: scope,
                    request: {
                        username: username,
                        password: password,
                        rememberMe: rememberMe
                    },
                    success: success
                });
            });

            it('success', function () {
                expect(dispatcher['checkpoint.signin']).toEqual('ok');
                expect(successCallbackExecuted).toEqual(true);
            });
        });
    });

    describe('SigninController', function () {
        beforeEach(inject(function (_$controller_, config) {
            binarta.checkpoint.profile.signout();
            $controller = _$controller_;
            config.namespace = 'namespace';
            config.redirectUri = 'redirect';
        }));

        describe('when unauthenticated', function () {
            describe('when username is in search part of url', function () {
                beforeEach(inject(function ($location, $controller) {
                    $location.search('username', username);
                    ctrl = $controller(SigninController, {$scope: scope});
                    $rootScope.$digest();
                }));

                it('username is on scope and ctrl', function () {
                    expect(scope.username).toEqual(username);
                    expect(ctrl.username).toEqual(username);
                });
            });

            describe('no params in search part of url', function () {
                beforeEach(function () {
                    ctrl = $controller(SigninController, {$scope: scope});
                    $rootScope.$digest();
                });

                it('username is not on scope and ctrl', function () {
                    expect(scope.username).toBeUndefined();
                    expect(ctrl.username).toBeUndefined();
                });

                [
                    'scope',
                    'controller'
                ].forEach(function (context) {
                    describe('with ' + context, function () {
                        var ctx;

                        beforeEach(function () {
                            if (context == 'scope') ctx = scope;
                            if (context == 'controller') ctx = ctrl;
                        });

                        it('on submit fire change event on inputs to make sure models are updated', function () {
                            ctx.submit();

                            expect(jQuerySelector).toEqual('form input[type="password"]');
                            expect(jQueryTriggeredEvent).toEqual('change');
                        });

                        function triggerSuccess(onSuccess) {
                            binarta.checkpoint.registrationForm.submit({username: username, password: password});
                            binarta.checkpoint.profile.signout();
                            ctx.username = username;
                            ctx.password = password;
                            ctx.submit({success: onSuccess});
                            $rootScope.$digest();
                        }

                        function triggerValidationError() {
                            ctx.username = '-';
                            ctx.password = '-';
                            ctx.submit();
                            $rootScope.$digest();
                        }

                        it('on submit success', function () {
                            triggerSuccess();

                            expect(location.path()).toEqual('/redirect');
                            expect(dispatcher['checkpoint.signin']).toEqual('ok');
                        });

                        it('on submit success with extra success callback', function () {
                            var onSuccessExecuted;
                            triggerSuccess(function () {
                                onSuccessExecuted = true;
                            });

                            expect(onSuccessExecuted).toEqual(true);
                        });

                        describe('with on signin success target', function () {
                            beforeEach(function () {
                                config.onSigninSuccessTarget = '/success/target';
                            });

                            it('on submit success', function () {
                                triggerSuccess();

                                expect(location.path()).toEqual('/success/target');
                                expect(config.onSigninSuccessTarget).toBeUndefined();
                                expect(ctx.violation).toEqual('');
                            });
                        });

                        it('on submit success with no redirect', function () {
                            location.path('/noredirect');
                            ctx.init({noredirect: true});

                            triggerSuccess();

                            expect(location.path()).toEqual('/noredirect');
                        });

                        it('expose rejection status', function () {
                            expect(scope.rejected()).toBeFalsy();
                            triggerValidationError();
                            expect(scope.rejected()).toBeTruthy();
                            expect(ctx.violation).toEqual('credentials.mismatch');
                        });
                    });
                });
            });
        });

        describe('when already signed in', function () {
            beforeEach(function () {
                binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                location.path('/path');
                ctrl = $controller(SigninController, {$scope: scope});
                $rootScope.$digest();
            });

            it('should redirect to homepage', function () {
                expect(location.path()).toEqual('/');
            });
        });
    });

    describe('AccountService', function () {
        var account, rootScope, topics, $location;

        beforeEach(inject(function (_account_, $rootScope, topicRegistryMock, _$location_) {
            $location = _$location_;
            account = _account_;
            rootScope = $rootScope;
            config.namespace = 'namespace';
            config.baseUri = 'base/';
            topics = topicRegistryMock;
        }));

        describe('on auth.required should call presenter', function () {
            beforeEach(function () {
                topics['checkpoint.auth.required']('/target/path');
            });

            it('set target path on config', function () {
                expect(config.onSigninSuccessTarget).toEqual('/target/path');
            });

            it('redirect to signin page', function () {
                expect($location.path()).toEqual('/signin');
            });
        });

        describe('get metadata', function () {
            var result, metadataAvailable;

            function callGetMetadata() {
                account.getMetadata().then(function (metadata) {
                    metadataAvailable = true;
                    result = metadata;
                }, function () {
                    metadataAvailable = false;
                    result = undefined;
                });
                rootScope.$digest();
            }

            describe('when signed out', function () {
                beforeEach(function () {
                    callGetMetadata();
                });

                it('then metadata is not available', function () {
                    expect(metadataAvailable).toBeFalsy();
                    expect(result).toBeUndefined();
                });

                it('on signin event then metadata is available', function () {
                    binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                    callGetMetadata();
                    expect(result.username).toEqual('u');
                });
            });

            describe('when signed in', function () {
                beforeEach(function () {
                    binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                });

                it('then metadata is available', function () {
                    callGetMetadata();
                    expect(result.username).toEqual('u');
                });

                it('then metadata can be resolved multiple times', function () {
                    callGetMetadata();
                    callGetMetadata();
                    expect(result.username).toEqual('u');
                });

                describe('when signed out', function () {
                    beforeEach(inject(function (binartaCheckpointGateway) {
                        binartaCheckpointGateway.signout();
                    }));

                    it('then after refresh caches then metadata is not available', inject(function () {
                        account.refreshCaches();
                        callGetMetadata();
                        expect(metadataAvailable).toBeFalsy();
                        expect(result).toBeUndefined();
                    }));

                    it('on signout event then metadata is not available', function () {
                        topics['checkpoint.signout']('ok');
                        callGetMetadata();
                        expect(metadataAvailable).toBeFalsy();
                        expect(result).toBeUndefined();
                    });

                    it('on auth.required event then metadata is not available', function () {
                        topics['checkpoint.auth.required']();
                        callGetMetadata();
                        expect(metadataAvailable).toBeFalsy();
                        expect(result).toBeUndefined();
                    });
                });
            });
        });

        describe('get permissions', function () {
            var permissions = [{name:'p1'}, {name:'p2'}, {name:'p3'}],
                result;

            function callGetPermissions() {
                account.getPermissions().then(function (permissions) {
                    result = permissions;
                });
            }

            beforeEach(function () {
                binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                account.refreshCaches();
                callGetPermissions();
            });

            it('first getPermissions call', function () {
                $rootScope.$apply();
                expect(result).toEqual(permissions);
            });

            it('second getPermissions call will return a cached promise using memoization', function () {
                result = undefined;
                account.getPermissions().then(function (permissions) {
                    result = permissions;
                });
                rootScope.$apply();

                expect(result).toEqual(permissions);
            });

            it('on signin should remove cached promise', function () {
                binarta.checkpoint.signinForm.eventRegistry.forEach(function(l) {
                    l.signedin();
                });

                callGetPermissions();
            });

            it('on signout should remove cached promise', function () {
                topics['checkpoint.signout']('ok');

                callGetPermissions();
            });

            it('on auth.required should remove cached promise', function () {
                topics['checkpoint.auth.required']();

                callGetPermissions();
            });
        });

        describe('has permission', function () {
            var metadata = {principal: 'foo'},
                permissions = [
                    {name: 'foo'},
                    {name: 'bar'},
                    {name: 'permission'}
                ];

            beforeEach(function () {
                binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                account.refreshCaches();
            });

            it('when permitted', function () {
                var permitted;
                account.hasPermission('p1').then(function (p) {
                    permitted = p;
                });
                $rootScope.$digest();
                expect(permitted).toEqual(true);
            });

            it('when not permitted', function () {
                var permitted;
                account.hasPermission('not').then(function (p) {
                    permitted = p;
                });
                $rootScope.$digest();

                expect(permitted).toEqual(false);
            });
        });
    });

    describe('FetchAccountMetadata', function () {
        var baseUri = 'base-uri/';
        var usecase, account;
        var payload = {principal: 'foo'};
        var response = {
            unauthorized: function () {
                response.status = 'unauthorized';
            },
            ok: function (metadata) {
                response.status = 'ok';
                response.metadata = metadata;
            }
        };
        var topics;

        beforeEach(inject(function (_account_, fetchAccountMetadata, topicRegistryMock) {
            account = _account_;
            usecase = fetchAccountMetadata;
            topics = topicRegistryMock;
            response.status = '';
            response.metadata = {};
        }));

        function assertUnauthorized() {
            expect(response.status).toEqual('unauthorized');
        }

        function assertOk() {
            expect(response.status).toEqual('ok');
            expect(response.metadata.principal).toBeDefined();
        }

        describe('when unauthenticated', function () {
            beforeEach(inject(function (binartaCheckpointGateway) {
                binartaCheckpointGateway.signout();
                account.refreshCaches();
                usecase(response);
                $rootScope.$digest();
            }));

            it('status is unauthorized', assertUnauthorized);

            describe('and checkpoint.signin event raised', function () {
                beforeEach(function () {
                    binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                    binarta.checkpoint.signinForm.eventRegistry.forEach(function(l) {
                        l.signedin();
                    });
                    usecase(response);
                    $rootScope.$digest();
                });

                it('status is ok', assertOk);
            });
        });

        describe('when unauthenticated and no callback defined', function () {
            beforeEach(function () {
                usecase({});
                $rootScope.$digest();
            });

            it('do not throw error', function () {
            });
        });

        describe('when authenticated', function () {
            beforeEach(function () {
                binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                account.refreshCaches();
                usecase(response);
                $rootScope.$digest();
            });

            it('status is ok', assertOk);

            describe('and checkpoint.signout event raised', function () {
                beforeEach(inject(function (binartaCheckpointGateway) {
                    binartaCheckpointGateway.signout();
                    topics['checkpoint.signout']('ok');
                    usecase(response);
                    $rootScope.$digest();
                }));

                it('status is unauthorized', function () {
                    assertUnauthorized();
                });
            });
        });

        describe('when authenticated and no callback defined', function () {
            beforeEach(function () {
                binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                account.refreshCaches();
                usecase({});
                $rootScope.$digest();
            });

            it('do not throw error', function () {
            });
        });

        describe('and response.scope is given', function () {
            var rootScope;
            beforeEach(inject(function ($rootScope) {
                rootScope = $rootScope;
                response.scope = $rootScope.$new();
            }));

            describe('when authenticated', function () {
                beforeEach(function () {
                    binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                    account.refreshCaches();
                    usecase(response);
                    $rootScope.$digest();
                });

                describe('and checkpoint.signout event raised', function () {
                    beforeEach(function () {
                        topics['checkpoint.signout']('ok');
                    });

                    it('status is unauthorized', function () {
                        assertUnauthorized();
                    });

                    describe('and checkpoint.signin event raised', function () {
                        beforeEach(function () {
                            topics['checkpoint.signin']('ok');
                            rootScope.$apply();
                        });

                        it('status is ok', function () {
                            assertOk();
                        });
                    });
                });
            });

            describe('when authenticated without callback on response', function () {
                beforeEach(function () {
                    binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
                    account.refreshCaches();
                    usecase({
                        scope: $rootScope.$new()
                    });
                });

                describe('and checkpoint.signout event raised', function () {
                    beforeEach(function () {
                        topics['checkpoint.signout']('ok');
                    });

                    it('do not throw error', function () {
                    });

                    describe('and checkpoint.signin event raised', function () {
                        beforeEach(function () {
                            topics['checkpoint.signin']('ok');
                            rootScope.$apply();
                        });

                        it('do not throw error', function () {
                        });
                    });
                });
            });
        });
    });

    describe('AccountMetadataController', function () {
        var registry, response;
        var payload = {};
        var presenter = jasmine.createSpy('presenter');

        beforeEach(inject(function ($controller, topicRegistryMock) {
            response = undefined;
            registry = topicRegistryMock;
            var usecase = function (it) {
                response = it
            };
            ctrl = $controller(AccountMetadataController, {
                $scope: scope,
                topicRegistry: registry,
                fetchAccountMetadata: usecase,
                authRequiredPresenter: presenter
            });
        }));

        it('scope is given to fetchAccountMetadata', function () {
            expect(response.scope).toEqual(scope);
        });

        it('fetch metadata unauthorized', function () {
            expect(scope.unauthorized()).toEqual(false);
            response.unauthorized();
            expect(scope.unauthorized()).toEqual(true);
        });

        it('fetch metadata success', function () {
            ctrl.status = 'unauthorized';
            expect(scope.unauthorized()).toEqual(true);
            expect(scope.authorized()).toEqual(false);
            response.ok(payload);
            expect(scope.unauthorized()).toEqual(false);
            expect(scope.authorized()).toEqual(true);
            expect(scope.metadata).toEqual(payload);
        });
    });

    describe('AuthRequiredPresenter', function () {
        var presenter;

        beforeEach(inject(function (authRequiredPresenter) {
            presenter = authRequiredPresenter;
        }));

        it('when presenting redirect for signin', function () {
            presenter('/previous/path');
            expect(location.path()).toEqual('/signin');
            expect(config.onSigninSuccessTarget).toEqual('/previous/path');
        });

        describe('when already on signin page', function () {
            beforeEach(function () {
                location.path('/signin');
                presenter('/signin');
            });

            it('should do nothing', function () {
                expect(config.onSigninSuccessTarget).not.toEqual('/signin');
            });
        });

        describe('with locale embedded in current route', function () {
            beforeEach(inject(function ($routeParams) {
                $routeParams.locale = 'lang';
            }));

            it('when presenting redirect for localized signin', function () {
                presenter('/previous/path');
                expect(location.path()).toEqual('/lang/signin');
            });

            describe('when already on signin page', function () {
                beforeEach(function () {
                    location.path('/signin');
                    presenter('/lang/signin');
                });

                it('should do nothing', function () {
                    expect(config.onSigninSuccessTarget).not.toEqual('/lang/signin');
                });
            });
        });
    });

    describe('ActiveUserHasPermission', function () {
        var usecase;
        var r, response;
        var account;
        var metadata = {principal: 'active-principal'},
            permissions = [
                {name: 'foo'},
                {name: 'bar'},
                {name: 'permission'}
            ];
        var topics;

        beforeEach(inject(function (activeUserHasPermission, _account_, topicRegistryMock) {
            config.baseUri = 'base-uri/';
            config.namespace = 'namespace';
            account = _account_;
            response = undefined;
            r = {
                yes: function () {
                    response = true;
                },
                no: function () {
                    response = false;
                }
            };
            topics = topicRegistryMock;
            usecase = activeUserHasPermission;
        }));

        function withPermission(permission) {
            binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
            account.refreshCaches();
            usecase(r, permission);
            $rootScope.$digest();
        }

        it('and unknown permission is rejected', function () {
            withPermission('unknown');

            expect(response).toEqual(false);
        });

        it('with known permission is accepted', function () {
            withPermission('p1');

            expect(response).toEqual(true);
        });

        it('and response.no is not given', function () {
            r.no = undefined;
            withPermission('unknown');
            expect(response).toBeUndefined();
        });

        it('and response.yes is not given', function () {
            r.yes = undefined;
            withPermission('p1');

            expect(response).toBeUndefined();
        });

        describe('and scope is not given with response', function () {
            describe('and usecase has triggered with known permission', function () {
                beforeEach(function () {
                    withPermission('p1');
                });

                describe('and signout', function () {
                    beforeEach(function () {
                        topics['checkpoint.signout']('ok');
                    });

                    it('permission is still accepted', function () {
                        expect(response).toEqual(true);
                    });
                });
            });
        });

        describe('and scope is given with response', function () {
            var scope;

            beforeEach(inject(function ($rootScope) {
                scope = $rootScope.$new();
                r.scope = scope;
            }));

            describe('and usecase has triggered', function () {
                beforeEach(function () {
                    withPermission('p1');
                });

                describe('and signout', function () {
                    beforeEach(function () {
                        topics['checkpoint.signout']('ok');
                    });

                    it('permission is rejected', function () {
                        expect(response).toEqual(false);
                    });

                    describe('and sign back in', function () {
                        beforeEach(inject(function ($rootScope) {
                            topics['checkpoint.signin']('ok');
                            $rootScope.$apply();
                        }));

                        it('permission is accepted', function () {
                            expect(response).toEqual(true);
                        });
                    });
                });
            });
        });
    });

    describe('checkpoint has directive', function () {
        var directive, registry, response, expectedPermission;

        beforeEach(inject(function ($log) {
            response = undefined;
            registry = function (scope, topic, listener) {
                registry[topic] = listener;
            };
            var usecase = function (it, permission) {
                response = it;
                expectedPermission = permission;
            };
            directive = CheckpointHasDirectiveFactory(registry, usecase, $log);
            scope = {};
            directive.link(scope, null, {for: 'permission'});
        }));

        it('is an element', function () {
            expect(directive.restrict).toEqual('A');
        });

        it('template', function () {
            expect(directive.transclude).toEqual(true);
            expect(directive.template).toEqual('<span ng-if="permitted" ng-transclude></span>');
        });

        it('link trigger usecase', function () {
            expect(response).toBeDefined();
            expect(expectedPermission).toEqual('permission');
        });

        it('not permitted', function () {
            response.no();
            expect(scope.permitted).toEqual(false);
        });

        it('permitted', function () {
            response.yes();
            expect(scope.permitted).toEqual(true);
        });

        ['checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
            it('handle ' + topic + ' notification', function () {
                response = undefined;
                expectedPermission = undefined;
                registry[topic]('ok');
                expect(response).toBeDefined();
                expect(expectedPermission).toEqual('permission');
            });
        });
    });

    describe('checkpointIsAuthenticated directive', function () {
        var directive, response;

        beforeEach(inject(function () {
            response = undefined;
            var usecase = function (it) {
                response = it;
            };
            directive = CheckpointIsAuthenticatedDirectiveFactory(usecase);
            scope = {};
            directive.link(scope);
        }));

        it('directive should create a child scope', function () {
            expect(directive.scope).toEqual(true);
        });

        it('link trigger usecase', function () {
            expect(response).toBeDefined();
        });

        it('unauthorized', function () {
            response.unauthorized();
            expect(scope.authenticated).toEqual(false);
        });

        it('authenticated', function () {
            response.ok();
            expect(scope.authenticated).toEqual(true);
        });

        it('scope is given to usecase', function () {
            expect(response.scope).toEqual(scope);
        });
    });

    describe('AuthenticatedWithRealmDirective', function () {
        var directive;
        var usecaseCalled;
        var response;
        var _topicRegistry;
        var _topicRegistryMock;
        var usecase = function (it) {
            usecaseCalled = true;
            response = it;
        };
        var registry = {
            subscribe: function (topic, listener) {
                registry[topic] = listener;
            }
        };


        beforeEach(inject(function ($rootScope, $injector) {
            scope = $rootScope.$new();
            _topicRegistry = $injector.get('topicRegistry');
            _topicRegistryMock = $injector.get('topicRegistryMock');
            directive = AuthenticatedWithRealmDirectiveFactory(usecase, registry);
        }));

        it('is an element', function () {
            expect(directive.restrict).toEqual('E');
        });

        it('defines own scope', function () {
            expect(directive.scope).toEqual({});
        });

        it('transcludes', function () {
            expect(directive.transclude).toEqual(true);
        });

        it('defines a template', function () {
            expect(directive.template).toEqual('<div ng-show="realm"><span ng-transclude></span></div>');
        });

        it('calls fetch account metadata', function () {
            directive.link(scope);
            registry['app.start']();
            expect(usecaseCalled).toBeTruthy();
        });

        it('false when unauthorized', function () {
            directive.link(scope);
            registry['app.start']();
            response.unauthorized();
            expect(scope.realm).toBeFalsy();
        });

        it('true when attr realm is equal to authenticated realm', function () {
            directive.link(scope, null, {realm: 'realm'});
            registry['app.start']();
            response.ok({realm: 'realm'});
            expect(scope.realm).toBeTruthy();
        });

        it('false when attr realm is not equal to authenticated realm', function () {
            directive.link(scope, null, {realm: 'invalid-realm'});
            registry['app.start']();
            response.ok({realm: 'realm'});
            expect(scope.realm).toBeFalsy();
        });

        ['checkpoint.signin', 'checkpoint.signout', 'app.start'].forEach(function (topic) {
            it('handle ' + topic + ' notification', function () {
                response = undefined;
                registry[topic]('ok');
                expect(response).toBeDefined();
            });
        });
    });

    describe('RegistrationController', function () {
        beforeEach(inject(function ($controller) {
            ctrl = $controller(RegistrationController, {$scope: scope});
            config.namespace = 'namespace';
        }));

        [
            'scope',
            'controller'
        ].forEach(function (context) {
            describe('with ' + context, function () {
                var ctx;
                beforeEach(function () {
                    if (context == 'scope') ctx = scope;
                    if (context == 'controller') ctx = ctrl;
                });

                describe('with invalid data', function () {
                    beforeEach(function () {
                        scope.registrationForm = {
                            $invalid: true,
                            email: {
                                $invalid: true
                            },
                            password: {
                                $invalid: true
                            },
                            vat: {
                                $invalid: true
                            }
                        };

                        ctx.register();
                    });

                    it('put violations on scope', function () {
                        expect(scope.violations).toEqual({
                            email: ['required'],
                            password: ['required'],
                            vat: ['required']
                        })
                    });
                });

                describe('given registration success', function () {
                    beforeEach(function () {
                        ctx.username = 'username';
                        ctx.email = 'email';
                        ctx.password = 'password';
                        ctx.vat = 'vat';
                    });

                    it('raises system.success notification', function () {
                        ctx.register();
                        expect(dispatcher['system.success']).toEqual({
                            code: 'checkpoint.registration.completed',
                            default: 'Congratulations, your account has been created.'
                        });
                    });

                    describe('on signin success', function () {
                        describe('and no success target defined', function () {
                            beforeEach(function () {
                                ctx.register();
                            });

                            it('redirect to homepage', function () {
                                expect(location.path()).toEqual('/');
                            });
                        });

                        describe('and success target is defined', function () {
                            beforeEach(function () {
                                config.onSigninSuccessTarget = '/target/';
                                ctx.register();
                            });

                            it('redirect to target', function () {
                                expect(location.path()).toEqual('/target/');
                            });

                            it('reset target config', function () {
                                expect(config.onSigninSuccessTarget).toBeUndefined();
                            });
                        });
                    });
                });

                describe('given registration rejected', function () {
                    beforeEach(function () {
                        ctx.username = 'invalid';
                        ctx.password = 'invalid';
                    });

                    it('raises checkpoint.registration.rejected notification', function () {
                        ctx.register();
                        expect(dispatcher['checkpoint.registration.rejected']).toEqual('rejected');
                    });
                });
            });
        });
    });

    describe('login modal directive', function () {
        var element, html, $rootScope, scope, modalSpy, config;

        beforeEach(inject(function (_$rootScope_, $compile, _modalSpy_, _config_) {
            config = _config_;
            $rootScope = _$rootScope_.$new();
            html = '<div login-modal></div>';
            element = angular.element(html);

            modalSpy = _modalSpy_;
            $compile(element)($rootScope);
            scope = element.scope();
            $rootScope.$digest();
        }));

        it('creates a child scope', function () {
            expect($rootScope).toEqual(scope.$parent);
        });

        it('open is called with default config', function () {
            scope.open();

            expect(modalSpy).toEqual({
                templateUrl: 'bower_components/binarta.checkpoint.angular/template/login-modal.html',
                backdrop: 'static'
            });
        });

        it('open is called with specific components dir in config', function () {
            config.componentsDir = 'components';

            scope.open();

            expect(modalSpy).toEqual({
                templateUrl: 'components/binarta.checkpoint.angular/template/login-modal.html',
                backdrop: 'static'
            });
        });

        it('open is called with specific styling in config', function () {
            config.styling = 'bootstrap3';

            scope.open();

            expect(modalSpy).toEqual({
                templateUrl: 'bower_components/binarta.checkpoint.angular/template/bootstrap3/login-modal.html',
                backdrop: 'static'
            });
        });
    });

    describe('checkpointWelcomeMessage controller', function () {
        var ctrl, $location, $controller;

        beforeEach(inject(function (_$location_, _$controller_) {
            $location = _$location_;
            $controller = _$controller_;
        }));

        describe('when welcome is in search part of url', function () {
            beforeEach(function () {
                $location.search('welcome', true);
                ctrl = $controller('welcomeMessageController');
            });

            it('welcome is available', function () {
                expect(ctrl.welcome).toBeTruthy();
            });

            describe('after route change', function () {
                beforeEach(function () {
                    $rootScope.$broadcast('$routeChangeStart');
                });

                it('remove welcome from search part', function () {
                    expect($location.search().welcome).toBeUndefined();
                });
            });
        });

        it('when welcome is not in search part of url', function () {
            ctrl = $controller('welcomeMessageController');

            expect(ctrl.welcome).toBeUndefined();
        });
    });

    describe('signInWithTokenService', function () {
        var service;

        beforeEach(inject(function (signInWithTokenService, _signinService_, $location) {
            service = signInWithTokenService;
            spyOn($location, 'replace');

            binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
            binarta.checkpoint.profile.signout();
        }));

        describe('with a token in the url', function () {
            beforeEach(inject(function ($location, $rootScope) {
                $location.search('autoSigninToken', 'token(u)');
            }));

            describe('and we attempt to sign in', function () {
                beforeEach(function () {
                    service()
                });

                it('then token is removed from location', inject(function ($location) {
                    expect($location.search().autoSigninToken).toBeUndefined();
                }));

                it('and the history state record was replaced', inject(function ($location) {
                    expect($location.replace).toHaveBeenCalled();
                }));
            });

            describe('and we attempt to sign in for a given token', function () {
                beforeEach(function () {
                    service({token: 'token(u)'})
                });

                it('then token is removed from location', inject(function ($location) {
                    expect($location.search().token).toBeUndefined();
                }));
            });
        });

        describe('without a token in the url', function () {
            describe('and we attempt to sign in', function () {
                beforeEach(function () {
                    service()
                });

                it('no signin attempt was made', function () {
                    expect(binarta.checkpoint.profile.isAuthenticated()).toBeFalsy();
                })
            });

            describe('and we attempt to sign in for a provided token', function () {
                beforeEach(function () {
                    service({token: 'token(u)'})
                });

                it('then a signin attempt for the given token was made', function () {
                    expect(binarta.checkpoint.profile.isAuthenticated()).toBeTruthy();
                })
            });
        });
    });
});
