package org.api.dto.user;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserResponse {
  private String email;
  private String token;
  private String username;
  private String bio;
  private String image;
}
