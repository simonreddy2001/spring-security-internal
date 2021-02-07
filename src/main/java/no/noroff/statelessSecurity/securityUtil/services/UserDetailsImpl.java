package no.noroff.statelessSecurity.securityUtil.services;

import com.fasterxml.jackson.annotation.JsonIgnore;
import no.noroff.statelessSecurity.models.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/*
    This class is our extension of the default UserDetails Spring Security has.
    It is extended to provide a way of accessing all the User entity fields as well as converting our
    roles into GrantedAuthority.
 */

public class UserDetailsImpl implements UserDetails {
    // Fields
    private Long id;

    private String username;

    private String email;

    // We dont want the password to be shown, so we simply ignore it.
    @JsonIgnore
    private String password;

    // This is what our roles will be represented as
    private Collection<? extends GrantedAuthority> authorities;

    // Constructor
    public UserDetailsImpl(Long id, String username, String email,
                           String password, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    // Build method to create a new UserDetailsImpl, this method converts our Role into GrantedAuthority
    public static UserDetailsImpl build(User user) {
        /*
         Here we use StreamAPI to create a list of GrantedAuthority from or role names.
         SimpleGrantedAuthority has a constructor that can take an argument that represents the role.
        */
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities);
    }

    // Extensions

    public String getEmail(){
        return email;
    }

    public Long getId(){
        return id;
    }

    // Overrides
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    /*
     The following override methods have their default configurations.
     We could implement logic in our application to handle the expiration of account and credentials
     and we could make a way to lock our users out.
     These are out of the scope of our project, but have merit in real world applications.
    */

    // Our accounts will never expire
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // Our accounts will never be locked
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // Our credentials never expire
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // All accounts are enabled by default
    @Override
    public boolean isEnabled() {
        return true;
    }

    // Two UserDetailImpl are equal when their Ids are equal
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}
