package no.noroff.statelessSecurity.models.domain;

import javax.persistence.*;

/*
    This class is responsible for creating the role table in our datastore. This has
    a many to many relationship with users. This will be the cornerstone of our access control.
 */

@Entity
@Table(name = "roles")
public class Role {
    // Our id is an integer, because we will never have over a billion roles. Its a waste of memory
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    /*
     We are setting the name field to a max of 15 as we will never need more than 15 characters for a role.
     This is done to save memory allocation as the default is 255.
    */
    @Enumerated(EnumType.STRING)
    @Column(length = 15)
    private RoleType name;

    // Constructors
    public Role() {
    }

    public Role(RoleType name) {
        this.name = name;
    }

    // Getters and setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public RoleType getName() {
        return name;
    }

    public void setName(RoleType name) {
        this.name = name;
    }
}
