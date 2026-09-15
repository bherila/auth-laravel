<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Tests\TestCase;

/** An application that binds no adapter exposes no delegated access route at all. */
class DelegatedAccessRouteRegistrationTest extends TestCase
{
    public function test_no_route_exists_without_an_adapter_even_when_enabled(): void
    {
        config(['bherila-auth.delegated_access.enabled' => true]);

        $this->assertNull(app('router')->getRoutes()->getByName('bherila-auth.delegated-access'));
        $this->post('/application-access')->assertNotFound();
    }
}
