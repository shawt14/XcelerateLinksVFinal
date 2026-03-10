using APIPSI16.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace APIPSI16.Migrations
{
    [DbContext(typeof(xcleratesystemslinks_SampleDBContext))]
    [Migration("20260310000001_AddEmployerCandidateHistoryDiscardAndPriority")]
    public partial class AddEmployerCandidateHistoryDiscardAndPriority : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsDiscarded",
                table: "EmployerCandidateHistory",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "PriorityId",
                table: "EmployerCandidateHistory",
                type: "int",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsDiscarded",
                table: "EmployerCandidateHistory");

            migrationBuilder.DropColumn(
                name: "PriorityId",
                table: "EmployerCandidateHistory");
        }
    }
}
