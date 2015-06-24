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
    var config = {namespace: 'namespace'};
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
            ctrl = $controller(ChangeMyPasswordController, {$scope: scope, config: config})
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

                    it('on init', function () {
                        expect(ctx.currentPassword).toEqual('');
                        expect(ctx.newPassword).toEqual('');
                        expect(ctx.submit).toBeDefined();
                        expect(ctx.forbidden).toEqual(false);
                    });

                    describe('on change my password send POST request', function () {
                        beforeEach(function () {
                            $httpBackend.expect('POST', 'api/account/password', {
                                currentPassword: currentPassword,
                                newPassword: newPassword
                            }).respond(200, '');

                            ctx.currentPassword = currentPassword;
                            ctx.newPassword = newPassword;
                            ctx.submit();

                            expect(ctx.ok).toEqual(false);
                            expect(ctx.forbidden).toEqual(false);

                            $httpBackend.flush();
                        });

                        it('ok flag is true', function () {
                            expect(ctx.ok).toEqual(true);
                        });

                        it('fields are reset', function () {
                            expect(ctx.currentPassword).toEqual('');
                            expect(ctx.newPassword).toEqual('');
                        });
                    });

                    it('on change with base uri', function () {
                        config.baseUri = 'http://host/context/';
                        $httpBackend.expect('POST', config.baseUri + 'api/account/password').respond(200);
                        ctx.submit();
                        $httpBackend.flush();
                    });

                    it('on change my password forbidden', function () {
                        $httpBackend.when('POST', /.*/).respond(403, '');

                        ctx.submit();
                        $httpBackend.flush();

                        expect(ctx.forbidden).toBe(true);
                    });
                });
            });
    });

    describe('RecoverPasswordController', function () {
        beforeEach(inject(function ($controller) {
            ctrl = $controller(RecoverPasswordController, {$scope: scope, config: config});
            presenter = {};
            usecaseAdapter.andReturn(presenter);
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

                    describe('on submit', function () {
                        [
                            'baseuri/',
                            null
                        ].forEach(function (uri) {
                                describe("with base uri = " + uri, function () {
                                    beforeEach(function () {
                                        config.baseUri = uri;
                                        ctx.email = 'email';
                                        ctx.submit();
                                    });

                                    it('violation is empty', function () {
                                        expect(ctx.violation).toEqual('');
                                    });

                                    it('creates presenter', function () {
                                        expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
                                    });

                                    it('sends PUT request', function () {
                                        expect(presenter.params.method).toEqual('PUT');
                                    });

                                    it('to the entity resource', function () {
                                        expect(presenter.params.url).toEqual((uri || '') + 'api/entity/password-reset-token');
                                    });

                                    it('passes data', function () {
                                        expect(presenter.params.data.namespace).toEqual(config.namespace);
                                        expect(presenter.params.data.email).toEqual(ctx.email);
                                    });

                                    it('sends rest call', function () {
                                        expect(rest.calls[0].args[0]).toEqual(presenter);
                                    });

                                    it('when rejected because email was empty', function () {
                                        usecaseAdapter.calls[0].args[2].rejected({
                                            email: ['required', 'email', 'mismatch']
                                        });

                                        expect(ctx.violation).toEqual('email.required');
                                    });

                                    it('when rejected because email was invalid', function () {
                                        usecaseAdapter.calls[0].args[2].rejected({
                                            email: ['email', 'mismatch']
                                        });

                                        expect(ctx.violation).toEqual('email.invalid');
                                    });

                                    it('when rejected because email was unknown', function () {
                                        usecaseAdapter.calls[0].args[2].rejected({
                                            email: ['mismatch']
                                        });

                                        expect(ctx.violation).toEqual('email.mismatch');
                                    });
                                });
                            });
                    });
                });
            });
    });

    describe('ResetPasswordController', function () {
        var resetPresenter = jasmine.createSpy('resetPasswordPresenter');

        describe('when username in query string', function () {
            beforeEach(inject(function ($controller) {
                location.search('username', 'clerk');
                ctrl = $controller(ResetPasswordController, {
                    $scope: scope,
                    config: config,
                    $location: location,
                    resetPasswordPresenter: resetPresenter
                });
            }));

            it('expose username on scope and ctrl', function () {
                expect(scope.username).toEqual('clerk');
                expect(ctrl.username).toEqual('clerk');
            });
        });

        beforeEach(inject(function ($controller) {
            ctrl = $controller(ResetPasswordController, {
                $scope: scope,
                config: config,
                $location: location,
                resetPasswordPresenter: resetPresenter
            });
            presenter = {};
            usecaseAdapter.andReturn(presenter);
        }));

        it('when username is not in query string', function () {
            expect(scope.username).toBeUndefined();
            expect(ctrl.username).toBeUndefined();
        });

        describe('on submit', function () {
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

                        [
                            null,
                            'baseuri/'
                        ].forEach(function (uri) {
                                describe('with base uri = ' + uri, function () {
                                    beforeEach(function () {
                                        config.baseUri = uri;
                                        ctx.password = 'new-password';
                                        scope.locale = 'locale';
                                        location.search('token', 'provided-token');
                                        ctx.submit();
                                    });

                                    it('violation is empty', function () {
                                        expect(ctx.violation).toEqual('');
                                    });

                                    it('creates presenter', function () {
                                        expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
                                    });

                                    it('sends POST request', function () {
                                        expect(presenter.params.method).toEqual('POST');
                                    });

                                    it('to the account resource', function () {
                                        expect(presenter.params.url).toEqual((uri || '') + 'api/account/reset/password');
                                    });

                                    it('passes data', function () {
                                        expect(presenter.params.data.namespace).toEqual(config.namespace);
                                        expect(presenter.params.data.password).toEqual(ctx.password);
                                        expect(presenter.params.data.token).toEqual('provided-token');
                                    });

                                    it('sends rest call', function () {
                                        expect(rest.calls[0].args[0]).toEqual(presenter);
                                    });

                                    it('when rejected because password was empy', function () {
                                        usecaseAdapter.calls[0].args[2].rejected({
                                            password: ['required']
                                        });

                                        expect(ctx.violation).toEqual('password.required');
                                    });

                                    it('when rejected because no token is given', function () {
                                        usecaseAdapter.calls[0].args[2].rejected({
                                            token: ['required']
                                        });

                                        expect(ctx.violation).toEqual('token.required');
                                    });

                                    it('when rejected because token is invalid', function () {
                                        usecaseAdapter.calls[0].args[2].rejected({
                                            token: ['mismatch']
                                        });

                                        expect(ctx.violation).toEqual('token.mismatch');
                                    });
                                });
                            });
                    });
                });
        });
    });

    describe('ResetPasswordPresenter', function () {
        var resetPresenter;

        beforeEach(inject(function (resetPasswordPresenter) {
            resetPresenter = resetPasswordPresenter;
        }));

        ['locale', null, ''].forEach(function (locale) {
            it('redirects to login with locale = ' + locale, function () {
                resetPresenter({locale: locale});
                expect(location.path()).toEqual((locale ? '/' + locale : '') + '/signin');
            });
        });

        it('when default locale do not use locale in uri', function () {
            resetPresenter({locale: 'default'});
            expect(location.path()).toEqual('/signin');
        });

        it('fires system success', function () {
            resetPresenter(scope);
            expect(dispatcher['system.success']).toEqual({
                code: 'checkpoint.reset.password.success',
                default: 'Password was successfully updated'
            });
        })
    });

    describe('RecoverPasswordPresenter', function () {
        var recoverPresenter;

        beforeEach(inject(function (recoverPasswordPresenter) {
            recoverPresenter = recoverPasswordPresenter;
        }));

        ['locale', null, ''].forEach(function (locale) {
            it('redirects to with locale = ' + locale, function () {
                recoverPresenter({locale: locale});
                expect(location.path()).toEqual((locale ? '/' + locale : '') + '/password/token/sent');
            });
        });

        it('when default locale do not use locale in uri', function () {
            recoverPresenter({locale: 'default'});
            expect(location.path()).toEqual('/password/token/sent');
        });
    });
});