/*
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.rapha.spring.reactive.security.api;

import io.rapha.spring.reactive.security.domain.FormattedMessage;
import io.rapha.spring.reactive.security.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

/**
 * A controller serving rest endpoints to show authorization features in this project
 * Endpoints for authentication are open, and others require the authenticated user to
 * have certain roles
 *
 * @author rafa
 */
@RestController
public class MessageController {

    @Autowired
    MessageService messageService;

    /**
     * Root endpoint serves as a resource for Basic Authentication
     *
     * @return A publisher that serves a welcoming message
     */
    @GetMapping("/")
    public Flux<FormattedMessage> hello() {
        return messageService.getDefaultMessage();
    }

    /**
     * Common login endpoint is also available for basic authentication
     *
     * @return A publisher serving a message stating successful log in
     */
    @GetMapping("/login")
    public Flux<FormattedMessage> login() {
        return messageService.getDefaultMessage();
    }

    /**
     * A restricted endpoint requiring consumers to be authenticated and also
     * have the right roles for this resource
     *
     * @return A publisher serving a message when access is granted
     */
    @GetMapping("/api/private")
    @PreAuthorize("hasRole('USER')")
    public Flux<FormattedMessage> privateMessage() {
        return messageService.getCustomMessage("User");
    }

    /**
     * A restricted endpoint requiring consumers to be authenticated and also
     * have the right roles for this resource
     *
     * @return A publisher serving a message when access is granted
     */
    @GetMapping("/api/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Flux<FormattedMessage> privateMessageAdmin() {
        return messageService.getCustomMessage("Admin");
    }

    /**
     * A restricted endpoint requiring consumers to be authenticated and also
     * have the right roles for this resource
     *
     * @return A publisher serving a message when access is granted
     */
    @GetMapping("/api/guest")
    @PreAuthorize("hasRole('GUEST')")
    public Flux<FormattedMessage> privateMessageGuest() {
        return messageService.getCustomMessage("Guest");
    }
}
