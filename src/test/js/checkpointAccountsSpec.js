describe('checkpoint accounts', function () {
    var scope, ctrl;
    var $httpBackend;
    var usecaseAdapter;
    var rest;
    var location;
    var router = {
        path: function (uri) {
            this.receivedUri = uri
        }
    };
    var presenter;
    var config = {namespace:'namespace'};
    var dispatcher;

    beforeEach(module('angular.usecase.adapter'));
    beforeEach(module('notifications'));
    beforeEach(module('rest.client'));
    beforeEach(module('checkpoint.accounts'));
    beforeEach(inject(function ($injector, $rootScope, usecaseAdapterFactory, restServiceHandler, $location, topicMessageDispatcherMock) {
        scope = $rootScope.$new();
        $httpBackend = $injector.get('$httpBackend');
        usecaseAdapter = usecaseAdapterFactory;
        rest = restServiceHandler;
        location = $location;
        dispatcher = topicMessageDispatcherMock;
    }));
    afterEach(function () {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('ChangeMyPasswordController', function () {
        var currentPassword = 'current-password';
        var newPassword = 'new-password';
        var config;

        beforeEach(inject(function ($controller) {
            config = {};
            ctrl = $controller(ChangeMyPasswordController, {$scope: scope, config:config})
        }));

        it('on init', function () {
            expect(scope.currentPassword).toEqual('');
            expect(scope.newPassword).toEqual('');
            expect(scope.submit).toBeDefined();
            expect(scope.forbidden).toEqual(false);
        });

        it('on change my password send POST request', function () {
            $httpBackend.expect('POST', 'account/password', {
                currentPassword: currentPassword,
                newPassword: newPassword
            }).respond(200, '');

            scope.currentPassword = currentPassword;
            scope.newPassword = newPassword;
            scope.submit();

            expect(scope.ok).toEqual(false);
            expect(scope.forbidden).toEqual(false);

            $httpBackend.flush();

            expect(scope.ok).toEqual(true);
        });

        it('on change with base uri', function() {
            config.baseUri = 'http://host/context/'
            $httpBackend.expect('POST', config.baseUri + 'account/password').respond(200);
            scope.submit();
            $httpBackend.flush();
        });

        it('on change my password forbidden', function () {
            $httpBackend.when('POST', /.*/).respond(403, '');

            scope.submit();
            $httpBackend.flush();

            expect(scope.forbidden).toBe(true);
        });
    });

    describe('RecoverPasswordController', function() {
        beforeEach(inject(function($controller) {
            ctrl = $controller(RecoverPasswordController, {$scope: scope, config: config});
            presenter = {};
            usecaseAdapter.andReturn(presenter);
        }));

        describe('on submit', function() {
            [
                'baseuri/',
                null
            ].forEach(function(uri) {
                describe("with base uri = " + uri, function() {
                    beforeEach(function() {
                        config.baseUri = uri;
                        scope.email = 'email';
                        scope.submit();
                    });

                    it('creates presenter', function() {
                        expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
                    });

                    it('sends PUT request', function() {
                        expect(presenter.params.method).toEqual('PUT');
                    });

                    it('to the entity resource', function() {
                        expect(presenter.params.url).toEqual((uri || '') + 'api/entity/password-reset-token');
                    });

                    it('passes data', function() {
                        expect(presenter.params.data.namespace).toEqual(config.namespace);
                        expect(presenter.params.data.email).toEqual(scope.email);
                    });

                    it('sends rest call', function() {
                        expect(rest.calls[0].args[0]).toEqual(presenter);
                    });
                });
            });
        });
    });

    describe('ResetPasswordController', function() {
        var resetPresenter = jasmine.createSpy('resetPasswordPresenter');

        describe('when username in query string', function() {
            beforeEach(inject(function($controller) {
                location.search('username', 'clerk');
                $controller(ResetPasswordController, {$scope:scope, config: config, $location: location, resetPasswordPresenter: resetPresenter});
            }));

            it('expose username on scope', function() {
                expect(scope.username).toEqual('clerk');
            });
        });

        beforeEach(inject(function($controller) {
            ctrl = $controller(ResetPasswordController, {$scope:scope, config: config, $location: location, resetPasswordPresenter: resetPresenter});
            presenter = {};
            usecaseAdapter.andReturn(presenter);
        }));

        it('when username is not in query string', function() {
            expect(scope.username).toBeUndefined();
        });

        describe('on submit', function() {
            [
                null,
                'baseuri/'
            ].forEach(function(uri) {
                    describe('with base uri = ' + uri, function() {
                        beforeEach(function() {
                            config.baseUri = uri;
                            scope.password = 'new-password';
                            scope.locale = 'locale';
                            location.search('token', 'provided-token');
                            scope.submit();
                        });

                        it('creates presenter', function() {
                            expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
                        });

                        it('sends POST request', function() {
                            expect(presenter.params.method).toEqual('POST');
                        });

                        it('to the account resource', function() {
                            expect(presenter.params.url).toEqual((uri || '') + 'api/account/reset/password');
                        });

                        it('passes data', function() {
                            expect(presenter.params.data.namespace).toEqual(config.namespace);
                            expect(presenter.params.data.password).toEqual(scope.password);
                            expect(presenter.params.data.token).toEqual('provided-token');
                        });

                        it('sends rest call', function() {
                            expect(rest.calls[0].args[0]).toEqual(presenter);
                        });
                    });
                });


        });
    });

    describe('ResetPasswordPresenter', function() {
        var resetPresenter;

        beforeEach(inject(function(resetPasswordPresenter) {
            resetPresenter = resetPasswordPresenter;
        }));

        ['locale', null, ''].forEach(function(locale) {
            it('redirects to login with locale = ' + locale, function() {
                resetPresenter({locale: locale});
                expect(location.path()).toEqual((locale ? '/' + locale : '') + '/signin');
            });
        });


        it('fires system success', function() {
            resetPresenter(scope);
            expect(dispatcher['system.success']).toEqual({code:'account.password.reset.success', default:'Password was successfully updated'});
        })
    });

    describe('RecoverPasswordPresenter', function() {
        var recoverPresenter;

        beforeEach(inject(function(recoverPasswordPresenter) {
            recoverPresenter = recoverPasswordPresenter;
        }));

        ['locale', null, ''].forEach(function(locale) {
            it('redirects to with locale = ' + locale, function() {
                recoverPresenter({locale: locale});
                expect(location.path()).toEqual((locale ? '/' + locale : '') + '/password/token/sent');
            });
        });
    });
});