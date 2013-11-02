describe('checkpoint accounts', function () {
    var scope, ctrl;
    var $httpBackend;
    var router = {
        path: function (uri) {
            this.receivedUri = uri
        }
    };

    beforeEach(inject(function ($injector, $rootScope) {
        scope = $rootScope.$new();
        $httpBackend = $injector.get('$httpBackend');
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
});