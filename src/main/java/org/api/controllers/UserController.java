package org.api.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.api.dto.user.*;
import org.api.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api")
@AllArgsConstructor
public class UserController {
  
  private final UserService userService;
  
  @PostMapping("/users/register")
  public ResponseEntity<UserResponse> register(
      @RequestBody RegisterRequest request,
      HttpServletResponse response
  ) {
    return new ResponseEntity<>(userService.register(request, response), HttpStatus.OK);
  }
  
  @PostMapping("/users/login")
  public ResponseEntity<UserResponse> login(
      @RequestBody LoginRequest request,
      HttpServletResponse response
  ) {
    return new ResponseEntity<>(userService.login(request, response), HttpStatus.OK);
  }

  @PreAuthorize("isAuthenticated()")
  @GetMapping("/user")
  public ResponseEntity<UserResponse> getCurrentUser(HttpServletRequest request) {
    return new ResponseEntity<>(userService.getCurrentUser(request), HttpStatus.OK);
  }

  @PreAuthorize("isAuthenticated()")
  @PutMapping("/user")
  public ResponseEntity<UserResponse> updateUser(@RequestBody UpdateRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
    return new ResponseEntity<>(userService.updateUser(request, httpRequest, httpResponse), HttpStatus.OK);
  }
  
  @GetMapping("/profiles/{username}")
  public ResponseEntity<ProfileResponse> getUserProfile(@PathVariable String username, HttpServletRequest request) {
    return new ResponseEntity<>(userService.getUserProfile(username, request), HttpStatus.OK);
  }

  @PreAuthorize("isAuthenticated()")
  @PostMapping("/profiles/{username}/follow")
  public ResponseEntity<ProfileResponse> followUser(@PathVariable String username, HttpServletRequest request) {
    return new ResponseEntity<>(userService.followUser(username, request), HttpStatus.OK);
  }

  @PreAuthorize("isAuthenticated()")
  @DeleteMapping("/profiles/{username}/follow")
  public ResponseEntity<ProfileResponse> unfollowUser(@PathVariable String username, HttpServletRequest request) {
    return new ResponseEntity<>(userService.unfollowUser(username, request), HttpStatus.OK);
  }
}
