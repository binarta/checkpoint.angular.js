describe('checkpoint', function () {
    var self = this;
    var ctrl, $rootScope, scope, $httpBackend, location, dispatcher, registry, config;
    var payload = {};
    var usecaseAdapter;
    var rest;
    var presenter;

    var username = 'johndoe';
    var password = '1234';
    var rememberMe = true;

    beforeEach(module('checkpoint'));
    beforeEach(module('rest.client'));
    beforeEach(module('notifications'));
    beforeEach(module('angular.usecase.adapter'));
    beforeEach(inject(function (_$rootScope_, $injector, $location, topicMessageDispatcherMock, topicRegistryMock, usecaseAdapterFactory, restServiceHandler) {
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
        usecaseAdapter.andReturn(presenter);
    }));
    afterEach(function () {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('SignoutController', function () {
        beforeEach(inject(function ($controller) {
            ctrl = $controller(SignoutController, {$scope: scope, config: {}});
        }));

        it('on submit send delete request', function () {
            $httpBackend.expect('DELETE', 'api/checkpoint').respond(0);
            scope.submit();
            $httpBackend.flush();
        });

        it('on submit success', function () {
            $httpBackend.expect('DELETE', /.*/).respond(200);
            scope.submit();
            $httpBackend.flush();
            expect(dispatcher['checkpoint.signout']).toEqual('ok');
        });
    });

    describe('SignoutController with baseUri', function () {
        beforeEach(inject(function ($controller) {
            ctrl = $controller(SignoutController, {
                $scope: scope,
                config: {baseUri: 'baseUri/'},
                topicMessageDispatcher: dispatcher
            });
        }));

        it('on submit send delete request', function () {
            $httpBackend.expect('DELETE', 'baseUri/api/checkpoint').respond(0);
            scope.submit();
            $httpBackend.flush();
        })
    });

    describe('SigninService', function () {
        var service;

        beforeEach(inject(function (config, signinService) {
            config.namespace = 'namespace';
            service = signinService;
        }));

        describe('on execute', function() {
            var successCallbackExecuted = false;
            var success = function() {
                successCallbackExecuted = true;
            };

            beforeEach(function() {
                service({
                    $scope: scope,
                    request: {
                        username: username,
                        password: password,
                        rememberMe: rememberMe
                    },
                    success:success
                });
            });

            it('send post request', function () {
                expect(rest.calls[0].args[0].params.method).toEqual('POST');
                expect(rest.calls[0].args[0].params.url).toEqual('api/checkpoint');
                expect(rest.calls[0].args[0].params.data).toEqual({
                    username: username,
                    password: password,
                    rememberMe: rememberMe,
                    namespace: 'namespace'
                });
                expect(rest.calls[0].args[0].params.withCredentials).toEqual(true);
            });

            it('success', function () {
                usecaseAdapter.calls[0].args[1]();
                expect(dispatcher['checkpoint.signin']).toEqual('ok');
                expect(successCallbackExecuted).toEqual(true);
            });
        });
    });

    describe('SigninController', function () {
        var $controller;

        beforeEach(inject(function (_$controller_, config) {
            $controller = _$controller_;
            config.namespace = 'namespace';
            config.redirectUri = 'redirect';
        }));

        describe('when unauthenticated', function () {
            describe('when username is in search part of url', function () {
                beforeEach(inject(function ($location, $controller) {
                    $location.search('username', username);
                    $httpBackend.expect('GET', /.*/).respond(401);
                    ctrl = $controller(SigninController, {$scope: scope});
                    $httpBackend.flush();
                }));

                it('username is on scope', function () {
                    expect(scope.username).toEqual(username);
                });
            });

            describe('no params in search part of url', function () {
                beforeEach(function () {
                    $httpBackend.expect('GET', /.*/).respond(401);
                    ctrl = $controller(SigninController, {$scope: scope});
                    $httpBackend.flush();
                });

                it('username is not on scope', function () {
                    expect(scope.username).toBeUndefined();
                });

                it('on submit send post request', function () {
                    scope.username = username;
                    scope.password = password;
                    scope.rememberMe = rememberMe;
                    scope.submit();

                    expect(rest.calls[0].args[0].params.method).toEqual('POST');
                    expect(rest.calls[0].args[0].params.url).toEqual('api/checkpoint');
                    expect(rest.calls[0].args[0].params.data).toEqual({
                        username: username,
                        password: password,
                        rememberMe: rememberMe,
                        namespace: 'namespace'
                    });
                    expect(rest.calls[0].args[0].params.withCredentials).toEqual(true);
                });

                function triggerSuccess(status, data, onSuccess) {
                    scope.submit({success: onSuccess});
                    if (status != 412)
                        usecaseAdapter.calls[0].args[1]();
                    else
                        usecaseAdapter.calls[0].args[2].rejected(data);
                }

                it('on submit success', function () {
                    triggerSuccess(200);

                    expect(location.path()).toEqual('/redirect');
                    expect(dispatcher['checkpoint.signin']).toEqual('ok');
                });

                it('on submit success with extra success callback', function () {
                    var onSuccessExecuted;
                    triggerSuccess(200, null, function () {
                        onSuccessExecuted = true;
                    });

                    expect(onSuccessExecuted).toEqual(true);
                });

                describe('with on signin success target', function () {
                    beforeEach(function () {
                        config.onSigninSuccessTarget = '/success/target';
                    });

                    it('on submit success', function () {
                        triggerSuccess(200);

                        expect(location.path()).toEqual('/success/target');
                        expect(config.onSigninSuccessTarget).toBeUndefined();
                        expect(scope.violation).toEqual('');
                    });
                });

                it('on submit success with no redirect', function () {
                    location.path('/noredirect');
                    scope.init({noredirect: true});

                    triggerSuccess(200);

                    expect(location.path()).toEqual('/noredirect');
                });

                it('expose rejection status', function () {
                    expect(scope.rejected()).toBeUndefined();
                    triggerSuccess(412, {});
                    expect(scope.rejected()).toEqual(true);
                    expect(scope.violation).toEqual('credentials.mismatch');
                });
            });
        });

        describe('when already signed in', function () {
            beforeEach(function() {
                location.path('/path');
                $httpBackend.expect('GET', /.*/).respond({principal: 'principal'});
                ctrl = $controller(SigninController, {$scope: scope});
                $httpBackend.flush();
            });

            it('should redirect to homepage', function () {
                expect(location.path()).toEqual('/');
            });
        });
    });

    describe('SigninController with baseUri', function () {
        var baseUri = 'baseUri';

        beforeEach(inject(function ($controller, config) {
            config.baseUri = baseUri;
            $httpBackend.expect('GET', /.*/).respond(401);
            ctrl = $controller(SigninController, {$scope: scope});
            $httpBackend.flush();
        }));

        it('on submit send post request', function () {
            scope.submit();
            expect(rest.calls[0].args[0].params.url).toEqual(baseUri + 'api/checkpoint');
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
            var validData = {principal: 'foo'},
                invalidData = {principal: null},
                result;

            function callGetMetadata(data) {
                $httpBackend.expect('GET', 'base/api/account/metadata', null, function(headers) {
                    return headers['X-Namespace'] == config.namespace;
                }).respond(data);
                account.getMetadata().then(function (metadata) {
                    result = metadata;
                });
                $httpBackend.flush();
            }

            it('when metadata is invalid', function () {
                callGetMetadata(invalidData);

                expect(result).toBeUndefined();
            });

            it('first getMetadata call', function () {
                callGetMetadata(validData);

                expect(result).toEqual(validData);
            });

            it('second getMetadata call will return a cached promise using memoization', function () {
                callGetMetadata(validData);
                result = undefined;
                account.getMetadata().then(function (metadata) {
                    result = metadata;
                });
                rootScope.$apply();

                expect(result).toEqual(validData);
            });

            it('on signin should remove cached promise', function () {
                callGetMetadata(validData);
                topics['checkpoint.signin']('ok');

                callGetMetadata(validData);
            });


            it('on signout should remove cached promise', function () {
                callGetMetadata(validData);
                topics['checkpoint.signout']('ok');

                callGetMetadata(validData);
            });

            it('on auth.required should remove cached promise', function () {
                callGetMetadata(validData);
                topics['checkpoint.auth.required']();

                callGetMetadata(validData);
            });
        });

        describe('get permissions', function () {
            var metadata = {principal: 'foo'},
                permissions = {permission: 'bar'},
                result;

            function callGetPermissions() {
                $httpBackend.expect('GET', 'base/api/account/metadata').respond(metadata);
                $httpBackend.expect('POST', 'base/api/query/permission/list', {filter: {namespace: config.namespace, owner: 'foo'}}).respond(permissions);
                account.getPermissions().then(function (permissions) {
                    result = permissions;
                });
                $httpBackend.flush();
            }

            beforeEach(function () {
                callGetPermissions();
            });

            it('first getPermissions call', function () {
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
                topics['checkpoint.signin']('ok');

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
    });

    describe('FetchAccountMetadata', function () {
        var baseUri = 'base-uri/';
        var usecase;
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

        beforeEach(inject(function (fetchAccountMetadata, topicRegistryMock) {
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
            expect(response.metadata).toEqual(payload);
        }

        it('on execute perform rest call', function () {
            config.baseUri = baseUri;
            config.namespace = 'namespace';
            $httpBackend.expect('GET', baseUri + 'api/account/metadata', null, function (headers) {
                return headers['X-Namespace'] == config.namespace;
            }).respond(0);
            usecase(response);
            $httpBackend.flush();
        });

        describe('when unauthenticated', function () {
            beforeEach(function () {
                $httpBackend.expect('GET', /.*/).respond(401);
                usecase(response);
                $httpBackend.flush();
            });

            it('status is unauthorized', assertUnauthorized);

            describe('and checkpoint.signin event raised', function () {
                beforeEach(function () {
                    topics['checkpoint.signin']('ok');
                    $httpBackend.expect('GET', /.*/).respond(200, payload);
                    usecase(response);
                    $httpBackend.flush();
                });

                it('status is ok', assertOk);
            });
        });

        describe('when authenticated', function () {
            beforeEach(function () {
                $httpBackend.expect('GET', /.*/).respond(200, payload);
                usecase(response);
                $httpBackend.flush();
            });

            it('status is ok', assertOk);

            describe('and checkpoint.signout event raised', function () {
                beforeEach(function () {
                    topics['checkpoint.signout']('ok');
                    $httpBackend.expect('GET', /.*/).respond(401);
                    usecase(response);
                    $httpBackend.flush();
                });

                it('status is unauthorized', function () {
                    assertUnauthorized();
                });
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
                    $httpBackend.expect('GET', /.*/).respond(200, payload);
                    usecase(response);
                    $httpBackend.flush();
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

        describe('with locale embedded in current route', function () {
            beforeEach(inject(function ($routeParams) {
                $routeParams.locale = 'lang';
            }));

            it('when presenting redirect for localized signin', function () {
                presenter('/previous/path');
                expect(location.path()).toEqual('/lang/signin');
            })
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
            $httpBackend.expect('GET', config.baseUri + 'api/account/metadata').respond(metadata);
            $httpBackend.expect('POST', config.baseUri + 'api/query/permission/list').respond(permissions);
            usecase(r, permission);
            $httpBackend.flush();
        }

        it('and unknown permission is rejected', function () {
            withPermission('unknown');

            expect(response).toEqual(false);
        });

        it('with known permission is accepted', function () {
            withPermission('permission');

            expect(response).toEqual(true);
        });

        it('and response.no is not given', function () {
            r.no = undefined;
            withPermission('unknown');
            expect(response).toBeUndefined();
        });

        it('and response.yes is not given', function () {
            r.yes = undefined;
            withPermission('permission');

            expect(response).toBeUndefined();
        });

        describe('and scope is not given with response', function () {
            describe('and usecase has triggered with known permission', function () {
                beforeEach(function () {
                    withPermission('permission');
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
                    withPermission('permission');
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

        beforeEach(inject(function () {
            response = undefined;
            registry = function (scope, topic, listener) {
                registry[topic] = listener;
            };
            var usecase = function (it, permission) {
                response = it;
                expectedPermission = permission;
            };
            directive = CheckpointHasDirectiveFactory(registry, usecase);
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

    describe('checkpointPermissionFor directive', function () {
        var directive, response, expectedPermission;

        beforeEach(inject(function () {
            response = undefined;
            var usecase = function (it, permission) {
                response = it;
                expectedPermission = permission;
            };
            directive = CheckpointPermissionForDirectiveFactory(usecase);
            scope = {};
            directive.link(scope, null, {checkpointPermissionFor: 'permission'});
        }));

        it('directive should create a child scope', function () {
            expect(directive.scope).toEqual(true);
        });

        it('link trigger usecase', function () {
            expect(response).toBeDefined();
            expect(expectedPermission).toEqual('permission');
        });

        it('scope is given to usecase', function () {
            expect(response.scope).toEqual(scope);
        });

        it('not permitted', function () {
            response.no();
            expect(scope.permitted).toEqual(false);
        });

        it('permitted', function () {
            response.yes();
            expect(scope.permitted).toEqual(true);
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
            scope.username = 'username';
            scope.email = 'email';
            scope.password = 'password';
            scope.vat = 'vat';
            scope.register();
        }));

        it('puts scope on presenter', function () {
            expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
        });

        it('populates params on presenter', function () {
            expect(presenter.params.method).toEqual('PUT');
            expect(presenter.params.url).toEqual('api/accounts');
            expect(presenter.params.data.namespace).toEqual(config.namespace);
            expect(presenter.params.data.username).toEqual(scope.username);
            expect(presenter.params.data.email).toEqual(scope.email);
            expect(presenter.params.data.alias).toEqual(scope.username);
            expect(presenter.params.data.password).toEqual(scope.password);
            expect(presenter.params.data.vat).toEqual(scope.vat);
        });

        it('populates params on presenter with base uri', function () {
            config.baseUri = 'baseUri/';
            scope.register();
            expect(presenter.params.method).toEqual('PUT');
            expect(presenter.params.url).toEqual('baseUri/api/accounts');
            expect(presenter.params.data.namespace).toEqual(config.namespace);
            expect(presenter.params.data.username).toEqual(scope.username);
            expect(presenter.params.data.email).toEqual(scope.email);
            expect(presenter.params.data.alias).toEqual(scope.username);
            expect(presenter.params.data.password).toEqual(scope.password);
            expect(presenter.params.data.vat).toEqual(scope.vat);
        });

        it('populates params on presenter based on registered mappers', inject(function (registrationRequestMessageMapperRegistry) {
            registrationRequestMessageMapperRegistry.add(function (scope) {
                return function (it) {
                    it.customField = scope.customField;
                    return it;
                }
            });
            scope.customField = '1234';
            scope.register();
            expect(presenter.params.data.customField).toEqual('1234');
        }));

        it('calls rest service', function () {
            expect(rest.calls[0].args[0]).toEqual(presenter);
        });

        describe('given registration success', function () {
            describe('and locale is known', function () {
                beforeEach(function () {
                    scope.locale = 'locale';
                    usecaseAdapter.calls[0].args[1]();
                });

                it('raises system.success notification', function () {
                    expect(dispatcher['system.success']).toEqual({
                        code: 'checkpoint.registration.completed',
                        default: 'Congratulations, your account has been created.'
                    });
                });

                it('redirects to root', function () {
                    expect(location.path()).toEqual('/locale/signin');
                });
            });

            describe('and locale is unknown', function () {
                beforeEach(function () {
                    usecaseAdapter.calls[0].args[1]();
                });

                it('raises system.success notification', function () {
                    expect(dispatcher['system.success']).toEqual({
                        code: 'checkpoint.registration.completed',
                        default: 'Congratulations, your account has been created.'
                    });
                });

                it('redirects to root', function () {
                    expect(location.path()).toEqual('/signin');
                });
            });
        });

        describe('given registration rejected', function () {
            beforeEach(function () {
                usecaseAdapter.calls[0].args[2].rejected();
            });

            it('raises checkpoint.registration.rejected notification', function () {
                expect(dispatcher['checkpoint.registration.rejected']).toEqual('rejected');
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

        it('when welcome is in search part of url', function () {
            $location.search('welcome', true);

            ctrl = $controller('welcomeMessageController');

            expect(ctrl.welcome).toBeTruthy();
        });

        it('when welcome is not in search part of url', function () {
            ctrl = $controller('welcomeMessageController');

            expect(ctrl.welcome).toBeUndefined();
        });
    });
});
