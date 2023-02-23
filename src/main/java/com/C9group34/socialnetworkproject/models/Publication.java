package com.C9group34.socialnetworkproject.models;


import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

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

    @Column(name = "status", nullable = false)
    private String status;


    @OneToMany(mappedBy = "publication", cascade = CascadeType.ALL)
    private List<Comment> comments;

    @OneToMany(mappedBy = "publication", cascade = CascadeType.ALL)
    private List<FavoritePublication> favoritePublications;

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinColumn(name = "category_id")
    private Category category;

    private Double calculateRating(){
        return null;
    }

}
