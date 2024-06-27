package org.api.services;

import lombok.AllArgsConstructor;
import org.api.entities.User;
import org.api.repositories.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
@AllArgsConstructor
public class UserDetailsImp implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    return new CustomUserDetails(user);
  }

  private record CustomUserDetails(User user) implements UserDetails {

    @Override
      public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
      }
  
      @Override
      public String getPassword() {
        return user.getPassword();
      }
  
      @Override
      public String getUsername() {
        return user.getEmail();
      }
    }
}