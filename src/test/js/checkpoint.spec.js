describe('checkpoint', function () {
    var self = this;
    var ctrl, scope, $httpBackend, location, dispatcher, registry, config;
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
    beforeEach(inject(function ($rootScope, $injector, $location, topicMessageDispatcherMock, topicRegistryMock, usecaseAdapterFactory, restServiceHandler) {
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
            ctrl = $controller(SignoutController, {$scope: scope, config: {baseUri: 'baseUri/'}, topicMessageDispatcher: dispatcher});
        }));

        it('on submit send delete request', function () {
            $httpBackend.expect('DELETE', 'baseUri/api/checkpoint').respond(0);
            scope.submit();
            $httpBackend.flush();
        })
    });

    describe('SigninController', function () {
        beforeEach(inject(function ($controller) {
            config = {namespace: 'namespace', redirectUri: 'redirect'};
            ctrl = $controller(SigninController, {$scope: scope, config: config});
        }));

        it('on submit send post request', function () {
            $httpBackend.expect('POST', 'api/checkpoint', {username: username, password: password, rememberMe: rememberMe, namespace: 'namespace'}).respond(200);

            scope.username = username;
            scope.password = password;
            scope.rememberMe = rememberMe;
            scope.submit();

            $httpBackend.flush();
        });

        it('on submit success', function () {
            $httpBackend.expect('POST', /.*/).respond(200);
            scope.submit();
            $httpBackend.flush();

            expect(location.path()).toEqual('/redirect');
            expect(dispatcher['checkpoint.signin']).toEqual('ok');
        });

        describe('with on signin success target', function() {
            beforeEach(function() {
                config.onSigninSuccessTarget = '/success/target';
            });

            it('on submit success', function() {
                $httpBackend.expect('POST', /.*/).respond(200);
                scope.submit();
                $httpBackend.flush();

                expect(location.path()).toEqual('/success/target');
                expect(config.onSigninSuccessTarget).toBeUndefined();
            });
        });

        it('on submit rejected', function () {
            $httpBackend.expect('POST', /.*/).respond(412, payload);
            scope.submit();
            $httpBackend.flush();

            expect(ctrl.status).toEqual(412);
            expect(ctrl.payload).toEqual(payload);
        });

        it('expose rejection status', function () {
            expect(scope.rejected()).toEqual(false);
            ctrl.status = 412;
            expect(scope.rejected()).toEqual(true);
        });

        it('expose rejection violations', function () {
            $httpBackend.expect('POST', /.*/).respond(412, {credentials: ['mismatch']});
            scope.submit();
            $httpBackend.flush();

            expect(scope.violations).toEqual([
                {context: 'credentials', cause: 'mismatch'}
            ]);
        });
    });

    describe('SigninController with baseUri', function () {
        var baseUri = 'baseUri';

        beforeEach(inject(function ($controller) {
            ctrl = $controller(SigninController, {$scope: scope, config: {baseUri: baseUri}});
        }));

        it('on submit send post request', function () {
            $httpBackend.expect('POST', baseUri + 'api/checkpoint', {username: username, password: password, rememberMe: rememberMe}).respond(200);

            scope.username = username;
            scope.password = password;
            scope.rememberMe = rememberMe;
            scope.submit();

            $httpBackend.flush();
        });
    });

    describe('FetchAccountMetadata', function () {
        var baseUri = 'base-uri/';
        var usecase;
        var registry;
        var payload = {};
        var response = {
            unauthorized: function () {
                response.status = 'unauthorized';
            },
            ok: function (metadata) {
                response.status = 'ok';
                response.metadata = metadata;
            }
        };

        beforeEach(inject(function (fetchAccountMetadata) {
            usecase = fetchAccountMetadata;
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
            $httpBackend.expect('GET', baseUri + 'api/account/metadata', null, function(headers) {
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

            it('results are cached', function () {
                response.status = undefined;
                usecase(response);
                assertUnauthorized();
            });

            describe('and checkpoint.signin event raised', function () {
                beforeEach(inject(function (topicRegistryMock) {
                    topicRegistryMock['checkpoint.signin']('ok');
                    $httpBackend.expect('GET', /.*/).respond(200, payload);
                    usecase(response);
                    $httpBackend.flush();
                }));

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

            it('results are cached', function () {
                response.status = undefined;
                response.metadata = undefined;
                usecase(response);
                assertOk();
            });

            describe('and checkpoint.signout event raised', function () {
                beforeEach(inject(function (topicRegistryMock) {
                    topicRegistryMock['checkpoint.signout']('ok');
                    $httpBackend.expect('GET', /.*/).respond(401);
                    usecase(response);
                    $httpBackend.flush();
                }));

                it('status is unauthorized', assertUnauthorized);
            });
        });
    });

    describe('AccountMetadataController', function () {
        var registry, response;
        var payload = {};

        beforeEach(inject(function ($controller, $http) {
            response = undefined;
            registry = {subscribe: function (topic, listener) {
                registry[topic] = listener;
            }};
            var usecase = function (it) {
                response = it
            };
            ctrl = $controller(AccountMetadataController, {$scope: scope, topicRegistry: registry, fetchAccountMetadata: usecase});
        }));

        ['app.start', 'checkpoint.signin', 'checkpoint.signout'].forEach(function (topic) {
            it('handle checkpoint.signin notification', function () {
                registry[topic]('ok');
            });
        });

        it('fetch metadata unauthorized', function () {
            registry['app.start']();
            expect(scope.unauthorized()).toEqual(false);
            response.unauthorized();
            expect(scope.unauthorized()).toEqual(true);
        });

        it('fetch metadata success', function () {
            registry['app.start']();
            ctrl.status = 'unauthorized';
            expect(scope.unauthorized()).toEqual(true);
            expect(scope.authorized()).toEqual(false);
            response.ok(payload);
            expect(scope.unauthorized()).toEqual(false);
            expect(scope.authorized()).toEqual(true);
            expect(scope.metadata).toEqual(payload);
        });

        it('on auth required notification redirect for signin', function () {
            registry['checkpoint.auth.required']('/previous/path');
            expect(location.path()).toEqual('/signin');
            expect(config.onSigninSuccessTarget).toEqual('/previous/path');
        });

        describe('with locale embedded in current route', function() {
            beforeEach(inject(function($routeParams) {
                $routeParams.locale = 'lang';
            }));

            it('on checkpoint.auth.required open localized signin route', function() {
                registry['checkpoint.auth.required']('/previous/path');
                expect(location.path()).toEqual('/lang/signin');
            });
        });
    });

    describe('ActiveUserHasPermission', function () {
        var usecase;
        var response;
        var r;
        var metadata = {principal: 'active-principal'};

        beforeEach(inject(function ($http, topicRegistry) {
            r = {
                yes: function () {
                    r.status = true;
                },
                no: function () {
                    r.status = false;
                }
            };
            response = undefined;
            var fetchAccountMetadata = function (it) {
                response = it
            };
            usecase = ActiveUserHasPermission(fetchAccountMetadata, topicRegistry, $http, {namespace: 'namespace'});
        }));

        function assertRejected() {
            expect(r.status).toEqual(false);
        }

        function assertAccepted() {
            expect(r.status).toEqual(true);
        }

        it('subscribes for config.initialized notifications', function () {
            expect(registry['config.initialized']).toBeDefined();
        });

        it('subscribes for checkpoint.signin notifications', function () {
            expect(registry['checkpoint.signin']).toBeDefined();
        });

        describe('with account metadata', function () {
            beforeEach(function () {
                usecase(r, 'permission');
            });

            describe('and signed out', function () {
                beforeEach(function () {
                    response.unauthorized();
                });

                it('permission rejected', assertRejected);
            });

            describe('and signed in', function () {

                function withPermission(permission, callback) {
                    return function () {
                        $httpBackend.expect('POST', 'api/query/permission/list', {filter: {namespace: 'namespace', owner: metadata.principal}}).respond(200, [
                            {name: permission}
                        ]);
                        response.ok(metadata);
                        $httpBackend.flush();
                        if (callback) callback();
                    }
                }

                it('query permissions', withPermission('irrelevant'));

                describe('and unknown permissions', function () {
                    beforeEach(withPermission('unknown'));

                    it('is rejected', assertRejected);

                    it('is cached', function () {
                        r.status = undefined;
                        usecase(r, 'permission');
                        response.ok(metadata);
                        assertRejected();
                    });
                });

                describe('and known permissions', function () {
                    beforeEach(withPermission('permission'));

                    it('with known permissions are accepted', assertAccepted);

                    it('is cached', function () {
                        r.status = undefined;
                        usecase(r, 'permission');
                        response.ok(metadata);
                        assertAccepted();
                    });

                    describe('on signin', function() {
                        beforeEach(function() {
                            r.status = undefined;
                            registry['checkpoint.signin']();
                            usecase(r, 'permission');
                        });
                        beforeEach(withPermission('modified'));

                        it('permission cache is cleared', function() {
                            assertRejected();
                        })
                    });
                });

            });

            describe('and config.initialized notification received with baseUri', function () {
                var config = {
                    baseUri: 'http://host/context/'
                };

                beforeEach(function () {
                    registry['config.initialized'](config);
                });

                it('and signed in', function () {
                    $httpBackend.expect('POST', config.baseUri + 'api/query/permission/list', {filter: {namespace: 'namespace', owner: metadata.principal}}).respond(200, []);
                    response.ok(metadata);
                    $httpBackend.flush();
                });
            });

            describe('and config.initialized notification received without baseUri', function () {
                var config = {};

                beforeEach(function () {
                    registry['config.initialized'](config);
                });

                it('and signed in', function () {
                    $httpBackend.expect('POST', 'api/query/permission/list', {filter: {namespace: 'namespace', owner: metadata.principal}}).respond(200, []);
                    response.ok(metadata);
                    $httpBackend.flush();
                });
            });
        });
    });

    describe('checkpoint has directive', function () {
        var directive, registry, response, expectedPermission;

        beforeEach(inject(function () {
            response = undefined;
            registry = {subscribe: function (topic, listener) {
                registry[topic] = listener;
            }};
            var usecase = function (it, permission) {
                response = it;
                expectedPermission = permission;
            };
            directive = CheckpointHasDirectiveFactory(registry, usecase);
            scope = directive.scope;
            directive.link(scope, null, {for: 'permission'});
        }));

        it('is an element', function () {
            expect(directive.restrict).toEqual('A');
        });

        it('declares a scope', function () {
            expect(directive.scope).toBeDefined();
        });

        it('template', function () {
            expect(directive.transclude).toEqual(true);
            expect(directive.template).toEqual('<span ng-show="permitted" ng-transclude></span>');
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

    describe('AuthenticatedWithRealmDirective', function() {
        var directive;
        var usecaseCalled;
        var response;
        var _topicRegistry;
        var _topicRegistryMock;
        var usecase = function(it) {
            usecaseCalled = true;
            response = it;
        };
        var registry = {subscribe: function (topic, listener) {
            registry[topic] = listener;
        }};


        beforeEach(inject(function($rootScope, $injector) {
            scope = $rootScope.$new();
            _topicRegistry = $injector.get('topicRegistry');
            _topicRegistryMock = $injector.get('topicRegistryMock');
            directive = AuthenticatedWithRealmDirectiveFactory(usecase, registry);
        }));

        it('is an element', function() {
            expect(directive.restrict).toEqual('E');
        });

        it('defines own scope', function() {
            expect(directive.scope).toEqual({});
        });

        it('transcludes', function() {
            expect(directive.transclude).toEqual(true);
        });

        it('defines a template', function() {
            expect(directive.template).toEqual('<div ng-show="realm"><span ng-transclude></span></div>');
        });

        it('calls fetch account metadata', function() {
            directive.link(scope);
            registry['app.start']();
            expect(usecaseCalled).toBeTruthy();
        });

        it('false when unauthorized', function() {
            directive.link(scope);
            registry['app.start']();
            response.unauthorized();
            expect(scope.realm).toBeFalsy();
        });

        it('true when attr realm is equal to authenticated realm', function() {
            directive.link(scope, null, {realm: 'realm'});
            registry['app.start']();
            response.ok({realm: 'realm'});
            expect(scope.realm).toBeTruthy();
        });

        it('false when attr realm is not equal to authenticated realm', function() {
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

    describe('RegistrationController', function() {
        beforeEach(inject(function($controller) {
            ctrl = $controller(RegistrationController, {$scope: scope});
            config.namespace = 'namespace';
            scope.username = 'username';
            scope.email = 'email';
            scope.password = 'password';
            scope.vat = 'vat';
            scope.register();
        }));

        it('puts scope on presenter', function() {
            expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
        });

        it('populates params on presenter', function() {
            expect(presenter.params.method).toEqual('PUT');
            expect(presenter.params.url).toEqual('api/accounts');
            expect(presenter.params.data.namespace).toEqual(config.namespace);
            expect(presenter.params.data.username).toEqual(scope.username);
            expect(presenter.params.data.email).toEqual(scope.email);
            expect(presenter.params.data.alias).toEqual(scope.username);
            expect(presenter.params.data.password).toEqual(scope.password);
            expect(presenter.params.data.vat).toEqual(scope.vat);
        });

        it('populates params on presenter with base uri', function() {
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

        it('populates params on presenter based on registered mappers', inject(function(registrationRequestMessageMapperRegistry) {
            registrationRequestMessageMapperRegistry.add(function(scope) {
                return function(it) {
                    it.customField = scope.customField;
                    return it;
                }
            });
            scope.customField = '1234';
            scope.register();
            expect(presenter.params.data.customField).toEqual('1234');
        }));

        it('calls rest service', function() {
            expect(rest.calls[0].args[0]).toEqual(presenter);
        });

        describe('given registration success', function() {
            beforeEach(function() {
                scope.locale = 'locale';
                usecaseAdapter.calls[0].args[1]();
            });

            it('raises system.success notification', function () {
                expect(dispatcher['system.success']).toEqual({
                    code:'checkpoint.registration.completed',
                    default:'Congratulations, your account has been created.'
                });
            });

            it('redirects to root', function() {
                expect(location.path()).toEqual('/locale/signin')
            });
        });

        describe('given registration rejected', function() {
            beforeEach(function() {
                usecaseAdapter.calls[0].args[2].rejected();
            });

            it('raises checkpoint.registration.rejected notification', function () {
                expect(dispatcher['checkpoint.registration.rejected']).toEqual('rejected');
            });
        });
    });
});
