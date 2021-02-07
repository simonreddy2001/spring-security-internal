package no.noroff.statelessSecurity.repositories;

import no.noroff.statelessSecurity.models.domain.Role;
import no.noroff.statelessSecurity.models.domain.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/*
 This is our RoleRepository, it is responsible for managing the domain entity Role.
 In addition to its default functionality, the RoleRepository needs to have a way to find a role by name.
*/

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(RoleType name);
}
