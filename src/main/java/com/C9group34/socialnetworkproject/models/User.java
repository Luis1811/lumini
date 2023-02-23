package com.C9group34.socialnetworkproject.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity(name = "users")
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private int id;

    @Schema(required = true)
    @Column(name = "name", nullable = false)
    private String name;

    @Schema(required = true)
    @Column(name = "surname", nullable = false)
    private String surname;

    @Schema(required = true)
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "phone")
    private String phone;

    @Schema(required = true)
    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "ratings")
    private Double ratings;

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinColumn(name = "role_id")
    private Role role;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Publication> publications;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<FavoritePublication> favoritePublications;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Conversation> conversations;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Participant> participant;

    public void modifyAttributeValue(String attributeName, Object newValue) {
        switch (attributeName) {
            case "name":
                this.name = (String) newValue;
                break;
            case "Surname":
                this.surname = (String) newValue;
                break;
            case "email":
                this.email = (String) newValue;
                break;
            case "phone":
                this.phone = (String) newValue;
                break;
            case "password":
                this.password = (String) newValue;
                break;
            case "ratings":
                this.ratings = Double.valueOf ((String)  newValue);
                break;
        }
    }



}
