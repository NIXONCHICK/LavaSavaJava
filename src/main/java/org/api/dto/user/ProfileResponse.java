package org.api.dto.user;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ProfileResponse {
  private String username;
  private String bio;
  private String image;
  private boolean following;
}
