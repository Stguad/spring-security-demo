package com.springboot.security.api.student.model;

public class Student {

	private Integer studentId;
	private String studentName;
	
	
	public Student(Integer studentId, String studentName) {
		this.studentId = studentId;
		this.studentName = studentName;
	}

	public void setStudentId(Integer studentId) {
		this.studentId = studentId;
	}
	
	public void setStudentName(String studentName) {
		this.studentName = studentName;
	}
	
	public Integer getStudentId() {
		return studentId;
	}
	
	public String getStudentName() {
		return studentName;
	}

	@Override
	public String toString() {
		return "Student [studentId=" + studentId + ", studentName=" + studentName + "]";
	}
	
	
	
	
}
