describe('checkpoint.oauth', function () {
    var ctrl, scope, $httpBackend;
    var rest, usecaseAdapter;
    var config = {namespace: 'namespace'};
    var presenter = {};

    beforeEach(module('checkpoint.oauth'));
    beforeEach(module('rest.client'));
    beforeEach(module('angular.usecase.adapter'));
    beforeEach(module('notifications'));
    beforeEach(inject(function ($rootScope, $injector, restServiceHandler, usecaseAdapterFactory) {
        scope = $rootScope.$new();
        $httpBackend = $injector.get('$httpBackend');
        rest = restServiceHandler;
        usecaseAdapter = usecaseAdapterFactory;
        usecaseAdapter.andReturn(presenter);
    }));

    afterEach(function () {
        presenter = {};
        config.baseUri = null;
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('OauthController', function () {

        beforeEach(inject(function ($controller) {
            ctrl = $controller(OauthController, {$scope: scope, restServiceHandler: rest, config: config});
        }));

        describe('authenticating with oauth', function () {
            beforeEach(function () {

                scope.auth();
            });

            it('passes scope to usecase adapter factory', function () {
                expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
            });

            it('params are set on presenter', function () {
                expect(presenter.params).toEqual({method: 'GET', url: 'api/oauth/authenticate/facebook', headers: {'X-Namespace': 'namespace'}})
            });

            it('generated presenter is passed to rest service', function () {
                expect(rest.calls[0].args[0]).toEqual(presenter);
            });

            describe('without configured baseUri', function () {
                it('url is resource without prefix', function () {
                    expect(presenter.params).toEqual({method: 'GET', url: 'api/oauth/authenticate/facebook', headers: {'X-Namespace': 'namespace'}})
                });
            });

            describe('with configured baseUri', function () {
                beforeEach(function () {
                    config.baseUri = 'baseUri/'
                    scope.auth();
                });

                it('url resource is prefixed with baseUri', function () {
                    expect(presenter.params).toEqual({method: 'GET', url: 'baseUri/api/oauth/authenticate/facebook', headers: {'X-Namespace': 'namespace'}})
                });
            });
        });

    });

    describe('CallbackController', function() {
        var $location;
        var _topicRegistry;
        var _topicRegistryMock;

        beforeEach(inject(function ($controller, $injector, topicRegistryMock, topicRegistry) {
            $location = $injector.get('$location');
            $location.search('code', 'some-code');
            _topicRegistry = topicRegistry;
            _topicRegistryMock = topicRegistryMock;
            ctrl = $controller(CallbackController, {$scope: scope, topicRegistry: topicRegistry, $location: $location, restServiceHandler: rest, usecaseAdapterFactory: usecaseAdapter, config: config});
        }));

        describe('with subscriber for app.start', function() {
            beforeEach(function() {
                scope.temp();
            });

            it('subscriber is defined', function() {
                expect(_topicRegistryMock['app.start']).toBeDefined();
            });

            describe('when subscriber is executed without configured baseUri', function() {
                beforeEach(function() {
                    _topicRegistryMock['app.start']();
                });

                it('passes scope to usecase adapter', function() {
                    expect(usecaseAdapter.calls[0].args[0]).toEqual(scope);
                });

                it('params are set on presenter', function () {
                    expect(presenter.params).toEqual({method: 'PUT', url: 'api/oauth/callback/facebook', data: {code: 'some-code'}, withCredentials:true, headers: {'X-Namespace': 'namespace'}})
                });

                it('calls rest service for presenter', function() {
                    expect(rest.calls[0].args[0]).toEqual(presenter);
                });

                describe('with configured baseUri', function () {
                    beforeEach(function() {
                        config.baseUri = 'baseUri/';
                        _topicRegistryMock['app.start']();
                    });

                    it('url resource is prefixed with baseUri', function () {
                        expect(presenter.params).toEqual({method: 'PUT', url: 'baseUri/api/oauth/callback/facebook', data: {code: 'some-code'}, withCredentials:true, headers: {'X-Namespace': 'namespace'}})
                    });
                });
            });
        });
    })
});