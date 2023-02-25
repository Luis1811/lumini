package com.C9group34.socialnetworkproject.models;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity(name="categories")
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class Category{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private int id;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "description")
    private String description;

    @OneToMany(mappedBy = "category", cascade = CascadeType.ALL)
    private List<Publication> publications;


}
