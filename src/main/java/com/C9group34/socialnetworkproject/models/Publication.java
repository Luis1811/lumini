package com.C9group34.socialnetworkproject.models;


import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity(name = "publications")
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class Publication {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private int id;


    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "description")
    private String description;

    @Column(name = "url_imgs", nullable = false)
    private String urlImg;

    @Column(name = "ratings", nullable = false)
    private Double rating;




    @OneToMany(mappedBy = "publication", cascade = CascadeType.ALL)
    private List<Comment> comments = new ArrayList<>();

    @OneToMany(mappedBy = "publication", cascade = CascadeType.ALL)
    private List<FavoritePublication> favoritePublications;

    @ManyToOne(fetch = FetchType.EAGER)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinColumn(name = "category_id")
    private Category category;

    public Double calculateRating(){
        return null;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User u) {
        this.user = u;
    }


    public void setCategory(Category c){
        this.category = c;
    }
    public void addComment(Comment c) {
        comments.add(c);
        c.setPublication(this);
    }

    public void removeComment(Comment c) {
        comments.remove(c);
        c.setPublication(null);
    }

    public void addFavoritePublication(FavoritePublication fp) {
        favoritePublications.add(fp);
        fp.setPublication(this);
    }

    public void removeFavoritePublication(FavoritePublication fp) {
        favoritePublications.remove(fp);
        fp.setPublication(null);
    }

}
