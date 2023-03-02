package com.C9group34.socialnetworkproject.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;

import java.util.Objects;

import java.util.List;

@Entity(name = "users")
@Table(name = "users")
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

    @Column(name = "img_profile")
    private String imgProfile;

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
    private List<Publication> publications = new ArrayList<Publication>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<FavoritePublication> favoritePublications = new ArrayList<FavoritePublication>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Conversation> conversations = new ArrayList<Conversation>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinColumn(name = "conversation_id")
    private Conversation participant;

    public void addPublication(Publication p) {
        publications.add(p);
        p.setUser(this);
    }

    public void removePublication(Publication p) {
        publications.remove(p);
        p.setUser(null);
    }

    //------------------------

    public void addFavoritePublication(FavoritePublication fp) {
        favoritePublications.add(fp);
        fp.setUser(this);
    }

    public void removeFavoritePublication(FavoritePublication fp) {
        favoritePublications.remove(fp);
        fp.setUser(null);

    }


    //-------------------------

    public void addConversation(Conversation c) {
        conversations.add(c);
        c.setUser(this);

    }

    public void removeConversation(Conversation c) {
        conversations.remove(c);
        c.setUser(null);

    }

}
