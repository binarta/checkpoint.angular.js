describe('checkpoint keepalive', function () {
    var binarta, config, dispatcher, keepalive, $httpBackend, $timeout, waitFor;

    beforeEach(module('checkpoint.keepalive'));

    beforeEach(inject(function (_config_, topicMessageDispatcherMock, _$httpBackend_, _$timeout_, _binarta_) {
        binarta = _binarta_;
        config = _config_;
        config.baseUri = 'base-uri/';
        dispatcher = topicMessageDispatcherMock;
        $httpBackend = _$httpBackend_;
        $timeout = _$timeout_;

        waitFor = function (ms) {
            $timeout.flush(ms);
        };
    }));

    describe('user is not logged in', function () {
        it('nothing should happen', function () {
            $timeout.verifyNoPendingTasks();
            $httpBackend.verifyNoOutstandingExpectation();
            $httpBackend.verifyNoOutstandingRequest();
        });
    });

    describe('when user is logged in', function () {
        beforeEach(function () {
            binarta.checkpoint.registrationForm.submit({username: 'u', password: 'p'});
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
                binarta.checkpoint.profile.signout();
            });

            it('no more keepalives', function () {
                waitFor(1200000);
                expect($httpBackend.flush).toThrow();
            });
        });
    });
});
