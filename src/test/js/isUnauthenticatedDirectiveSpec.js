describe('something', function() {
    var scope;
    var directive;
    var usecase;
    var usecaseCalled;
    var response;

    beforeEach(module('checkpoint'));
    beforeEach(inject(function($rootScope, $log) {
        usecase = function(it) {
            usecaseCalled = true;
            response = it;
        };
        scope = $rootScope.$new();
        directive = IsUnauthenticatedDirectiveFactory(usecase, $log);
        directive.link(scope)
    }));

    it('is an element', function() {
        expect(directive.restrict).toEqual('E');
    });

    it('declares a scope', function() {
        expect(directive.scope).toEqual({});
    });

    it('uses a template', function() {
        expect(directive.transclude).toEqual(true);
        expect(directive.template).toEqual('<div ng-show="unauthenticated"><span ng-transclude></span></div>');
    });

    it('calls usecase', function() {
        expect(usecaseCalled).toBeTruthy();
    });

    it('response ok', function() {
        response.ok();
        expect(scope.unauthenticated).toBeFalsy();
    });

    it('response unauthorized', function() {
        response.unauthorized();
        expect(scope.unauthenticated).toBeTruthy();
    });
});