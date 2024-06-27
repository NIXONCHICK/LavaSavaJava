package org.api.repositories;

import org.api.entities.Subscription;
import org.api.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SubscriptionRepository extends JpaRepository<Subscription, Long> {
  Optional<Subscription> findBySubscriberAndSubscribedTo(User subscriber, User subscribedTo);
}