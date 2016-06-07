describe('checkpoint keepalive', function () {
    var fetchAccountMetadata, config, dispatcher, keepalive, $httpBackend, $window, $timeout, waitFor;

    beforeEach(module('notifications'));
    beforeEach(module('checkpoint.keepalive'));

    beforeEach(function () {
        module(function ($provide) {
            $provide.service('fetchAccountMetadata', function () {
                return jasmine.createSpy('fetchAccountMetadata');
            })
        });
    });

    beforeEach(inject(function ($rootScope, _config_, topicMessageDispatcherMock, _fetchAccountMetadata_, _$httpBackend_, _$window_, _$timeout_) {
        fetchAccountMetadata = _fetchAccountMetadata_;
        config = _config_;
        config.baseUri = 'base-uri/';
        dispatcher = topicMessageDispatcherMock;
        $httpBackend = _$httpBackend_;
        $window = _$window_;
        $timeout = _$timeout_;

        waitFor = function (ms) {
            $timeout.flush(ms);
        };
    }));

    describe('user is logged out', function () {
        beforeEach(function () {
            fetchAccountMetadata.calls.first().args[0].unauthorized();
        });

        it('nothing should happen', function () {
            $timeout.verifyNoPendingTasks();
            $httpBackend.verifyNoOutstandingExpectation();
            $httpBackend.verifyNoOutstandingRequest();
        });

        it('no focus event on window', function () {
            expect($window.onfocus).toEqual(null);
        });
    });

    describe('when user is logged in', function () {
        beforeEach(function () {
            fetchAccountMetadata.calls.first().args[0].ok();
        });

        afterEach(function () {
            $httpBackend.verifyNoOutstandingExpectation();
            $httpBackend.verifyNoOutstandingRequest();
        });

        it('before timeout is reached, no keepalive is called', function () {
            waitFor(1199999);
            expect($httpBackend.flush).toThrow();
        });


        it('keepalive is called', function () {
            $httpBackend.expectGET('base-uri/api/keepalive').respond(200);
            waitFor(1200000);
            $httpBackend.flush(1);
        });

        it('keepalive is called multiple times', function () {
            $httpBackend.expectGET('base-uri/api/keepalive').respond(200);
            waitFor(1200000);
            $httpBackend.flush(1);

            $httpBackend.expectGET('base-uri/api/keepalive').respond(200);
            waitFor(1200000);
            $httpBackend.flush(1);

            $httpBackend.expectGET('base-uri/api/keepalive').respond(200);
            waitFor(1200000);
            $httpBackend.flush(1);
        });

        it('on window focus', function () {
            $httpBackend.expectGET('base-uri/api/keepalive').respond(200);
            $window.onfocus();
            $httpBackend.flush(1);
        });

        describe('when keepalive is unauthorized', function () {
            beforeEach(function () {
                $httpBackend.expectGET('base-uri/api/keepalive').respond(401);
                waitFor(1200000);
                $httpBackend.flush(1);
            });

            it('send notification', function () {
                expect(dispatcher['system.info']).toEqual({
                    code: 'checkpoint.session.expired',
                    persistent: true
                });
            });
        });

        describe('user logs out', function () {
            beforeEach(function () {
                fetchAccountMetadata.calls.first().args[0].unauthorized();
            });

            it('no more keepalives', function () {
                waitFor(1200000);
                expect($httpBackend.flush).toThrow();
            });
        });
    });
});
