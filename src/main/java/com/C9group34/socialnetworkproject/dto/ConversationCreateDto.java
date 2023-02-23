package com.C9group34.socialnetworkproject.dto;

public class ConversationCreateDto {
    private Integer id;
    private String title;
    private int creator_id;
    private String content;
    private int user_id;

    public ConversationCreateDto() { }
    public ConversationCreateDto(Integer id, String title, int creator_id, String content, int user_id) {
        this.id = id;
        this.title = title;
        this.creator_id = creator_id;
        this.content = content;
        this.user_id = user_id;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public int getCreator() { return creator_id; }
    public void setCreator(int creator_id) { this.creator_id = creator_id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public int getUser() { return user_id; }
    public void setUser(int user_id) { this.user_id = user_id; }
}
