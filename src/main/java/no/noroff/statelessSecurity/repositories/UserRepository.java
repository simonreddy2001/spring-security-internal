package no.noroff.statelessSecurity.repositories;

import no.noroff.statelessSecurity.models.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/*
 This is our UserRepository, it is responsible for manipulating the domain entity User.
 In addition to the default functionality, we need extra methods for our unique business logic.
 We need a way to find a user by their username, to see if a user exists for a given username, and
 to see if a user exists for a given email.
*/

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
