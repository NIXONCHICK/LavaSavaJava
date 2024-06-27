package org.api.services;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.api.dto.user.*;
import org.api.entities.Subscription;
import org.api.entities.User;
import org.api.repositories.SubscriptionRepository;
import org.api.repositories.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService {
  
  private final UserRepository userRepository;
  private final SubscriptionRepository subscriptionRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public UserResponse register(
      RegisterRequest request,
      HttpServletResponse response
  ) {
    User user = User.builder()
        .username(request.getUsername())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .build();
    userRepository.save(user);

    String token = generateTokenAndAddToCookies(user, response);
    
    return createUserResponse(user, token);
  }
  
  public UserResponse login(
      LoginRequest request,
      HttpServletResponse response
  ) {
    User user = userRepository.findByEmail(request.getEmail())
        .orElseThrow(() -> new RuntimeException("User not found"));

    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );

    String token = generateTokenAndAddToCookies(user, response);

    return createUserResponse(user, token);
  }
  
  public UserResponse getCurrentUser(HttpServletRequest request) {
    String token = jwtService.extractTokenFromCookies(request);
    User user = userRepository.findById(jwtService.extractId(token))
        .orElseThrow(() -> new RuntimeException("User not found"));
    
    return createUserResponse(user, token);
  }

  public UserResponse updateUser(
      UpdateRequest request, 
      HttpServletRequest httpRequest,
      HttpServletResponse httpResponse
      
  ) {
    String token = jwtService.extractTokenFromCookies(httpRequest);
    User user = userRepository.findById(jwtService.extractId(token))
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    boolean flag = !Objects.equals(user.getEmail(), request.getEmail()) && request.getEmail() != null;
    
    if (request.getEmail() != null) {
      user.setEmail(request.getEmail());
    }
    if (request.getUsername() != null) {
      user.setUsername(request.getUsername());
    }
    if (request.getPassword() != null) {
      user.setPassword(passwordEncoder.encode(request.getPassword()));
    }
    if (request.getImage() != null) {
      user.setImage(request.getImage());
    }
    if (request.getBio() != null) {
      user.setBio(request.getBio());
    }

    userRepository.save(user);
    if(flag){
      token = generateTokenAndAddToCookies(user, httpResponse);
    }
    
    return createUserResponse(user, token);
  }

  public ProfileResponse getUserProfile(String username, HttpServletRequest request) {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new RuntimeException("User not found"));

    ProfileResponse response = createProfileResponse(user);

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.isAuthenticated()) {
      String token = jwtService.extractTokenFromCookies(request);
      User currentUser = userRepository.findById(jwtService.extractId(token))
          .orElseThrow(() -> new RuntimeException("User not found"));
      Optional<Subscription> subscription = subscriptionRepository.findBySubscriberAndSubscribedTo(currentUser, user);
      response.setFollowing(subscription.isPresent());
    }

    return response;
  }

  public ProfileResponse followUser(String username, HttpServletRequest request) {
    String token = jwtService.extractTokenFromCookies(request);
    User currentUser = userRepository.findById(jwtService.extractId(token))
        .orElseThrow(() -> new RuntimeException("User not found"));
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new RuntimeException("User not found"));

    Optional<Subscription> existingSubscription = subscriptionRepository.findBySubscriberAndSubscribedTo(currentUser, user);
    if (existingSubscription.isEmpty()) {
      Subscription subscription = Subscription.builder()
          .subscriber(currentUser)
          .subscribedTo(user)
          .build();
      subscriptionRepository.save(subscription);
    }

    ProfileResponse response = createProfileResponse(user);
    response.setFollowing(true);

    return response;
  }
  
  public ProfileResponse unfollowUser(String username, HttpServletRequest request) {
    String token = jwtService.extractTokenFromCookies(request);
    User currentUser = userRepository.findById(jwtService.extractId(token))
        .orElseThrow(() -> new RuntimeException("User not found"));
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new RuntimeException("User not found"));

    Optional<Subscription> existingSubscription = subscriptionRepository.findBySubscriberAndSubscribedTo(currentUser, user);
    existingSubscription.ifPresent(subscriptionRepository::delete);

    return createProfileResponse(user);
  }
  
  private UserResponse createUserResponse(User user, String token) {
    return UserResponse.builder()
        .username(user.getUsername())
        .email(user.getEmail())
        .token(token)
        .bio(user.getBio())
        .image(user.getImage())
        .build();
  }
  
  private ProfileResponse createProfileResponse(User user) {
    return ProfileResponse.builder()
        .username(user.getUsername())
        .bio(user.getBio())
        .image(user.getImage())
        .following(false)
        .build();
  }

  private String generateTokenAndAddToCookies(User user, HttpServletResponse response) {
    String token = jwtService.generateToken(user);
    Cookie cookie = new Cookie("token", token);
    cookie.setHttpOnly(true);
    cookie.setPath("/");
    response.addCookie(cookie);
    
    return token;
  }
}
