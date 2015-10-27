angular.module("checkpoint.keepalive", ['checkpoint', 'config', 'notifications'])
    .run(['$rootScope', '$timeout', '$http', '$window', 'config', 'fetchAccountMetadata', 'topicMessageDispatcher',
        function ($rootScope, $timeout, $http, $window, config, fetchAccountMetadata, topicMessageDispatcher) {
            var signedIn;

            fetchAccountMetadata({
                ok: function () {
                    signedIn = true;
                    keepAliveRecurring();
                    $window.onfocus = keepAlive;
                },
                unauthorized: function () {
                    signedIn = false;
                    $window.onfocus = null;
                },
                scope: $rootScope
            });

            function keepAlive(args) {
                $http.get(config.baseUri + 'api/keepalive', {
                    withCredentials: true
                }).then(function () {
                    if (args && args.onSuccess) args.onSuccess();
                }, function (error) {
                    if (error.status == 401) topicMessageDispatcher.fire('system.info', {
                        code: 'checkpoint.session.expired',
                        persistent: true
                    });
                });
            }

            function keepAliveRecurring() {
                $timeout(function () {
                    if (signedIn) keepAlive({onSuccess: keepAliveRecurring});
                }, 1200000);
            }
    }]);